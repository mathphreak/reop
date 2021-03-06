/*
 * Copyright (c) 2014 Ted Unangst <tedu@tedunangst.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <arpa/inet.h>

#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <readpassphrase.h>
#include <util.h>
#include <reopbase64.h>

#include <sodium.h>

#include "reop.h"

/* shorter names */
#define SIGBYTES crypto_sign_ed25519_BYTES
#define SIGSECRETBYTES crypto_sign_ed25519_SECRETKEYBYTES
#define SIGPUBLICBYTES crypto_sign_ed25519_PUBLICKEYBYTES

#define ENCSECRETBYTES crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
#define ENCPUBLICBYTES crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#define ENCNONCEBYTES crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
#define ENCZEROBYTES crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
#define ENCBOXZEROBYTES crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
#define ENCTAGBYTES crypto_box_curve25519xsalsa20poly1305_MACBYTES

#define SYMKEYBYTES crypto_secretbox_xsalsa20poly1305_KEYBYTES
#define SYMNONCEBYTES crypto_secretbox_xsalsa20poly1305_NONCEBYTES
#define SYMZEROBYTES crypto_secretbox_xsalsa20poly1305_ZEROBYTES
#define SYMBOXZEROBYTES crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES
#define SYMTAGBYTES crypto_secretbox_xsalsa20poly1305_MACBYTES

/* magic */
#define SIGALG "Ed"	/* Ed25519 */
#define ENCALG "eC"	/* ephemeral Curve25519-Salsa20 */
#define OLDENCALG "CS"	/* Curve25519-Salsa20 */
#define ENCKEYALG "CS"	/* same as "old", didn't change */
#define OLDEKCALG "eS"	/* ephemeral-curve25519-Salsa20 */
#define SYMALG "SP"	/* Salsa20-Poly1305 */
#define KDFALG "BK"	/* bcrypt kdf */
#define IDENTLEN 64
#define RANDOMIDLEN 8
#define REOP_BINARY "RBF"

/* metadata */
/* these types are holdovers from before */
struct oldencmsg {
	uint8_t encalg[2];
	uint8_t secrandomid[RANDOMIDLEN];
	uint8_t pubrandomid[RANDOMIDLEN];
	uint8_t nonce[ENCNONCEBYTES];
	uint8_t tag[ENCTAGBYTES];
};

struct oldekcmsg {
	uint8_t ekcalg[2];
	uint8_t pubrandomid[RANDOMIDLEN];
	uint8_t pubkey[ENCPUBLICBYTES];
	uint8_t nonce[ENCNONCEBYTES];
	uint8_t tag[ENCTAGBYTES];
};

/*
 * new types
 * everything up to the ident is stored base64 encoded.
 * the ident is stored on a line by itself.
 */
struct reop_seckey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint8_t randomid[RANDOMIDLEN];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t nonce[SYMNONCEBYTES];
	uint8_t tag[SYMTAGBYTES];
	uint8_t sigkey[SIGSECRETBYTES];
	uint8_t enckey[ENCSECRETBYTES];
	char ident[IDENTLEN];
};
const size_t seckeysize = offsetof(struct reop_seckey, ident);

struct reop_sig {
	uint8_t sigalg[2];
	uint8_t randomid[RANDOMIDLEN];
	uint8_t sig[SIGBYTES];
	char ident[IDENTLEN];
};
const size_t sigsize = offsetof(struct reop_sig, ident);

struct reop_pubkey {
	uint8_t sigalg[2];
	uint8_t encalg[2];
	uint8_t randomid[RANDOMIDLEN];
	uint8_t sigkey[SIGPUBLICBYTES];
	uint8_t enckey[ENCPUBLICBYTES];
	char ident[IDENTLEN];
};
const size_t pubkeysize = offsetof(struct reop_pubkey, ident);

struct reop_symmsg {
	uint8_t symalg[2];
	uint8_t kdfalg[2];
	uint32_t kdfrounds;
	uint8_t salt[16];
	uint8_t nonce[SYMNONCEBYTES];
	uint8_t tag[SYMTAGBYTES];
};
const size_t symmsgsize = sizeof(struct reop_symmsg);

struct reop_encmsg {
	uint8_t encalg[2];
	uint8_t secrandomid[RANDOMIDLEN];
	uint8_t pubrandomid[RANDOMIDLEN];
	uint8_t ephpubkey[ENCPUBLICBYTES];
	uint8_t ephnonce[ENCNONCEBYTES];
	uint8_t ephtag[ENCTAGBYTES];
	uint8_t nonce[ENCNONCEBYTES];
	uint8_t tag[ENCTAGBYTES];
	char ident[IDENTLEN];
};
const size_t encmsgsize = offsetof(struct reop_encmsg, ident);


/* utility */
static int
xopen(const char *filename, int oflags, mode_t mode)
{
	struct stat sb;
	int fd;

	if (strcmp(filename, "-") == 0) {
		if ((oflags & O_WRONLY))
			fd = dup(STDOUT_FILENO);
		else
			fd = dup(STDIN_FILENO);
		if (fd == -1)
			return -2;
	} else {
		fd = open(filename, oflags, mode);
		if (fd == -1)
			return -1;
	}
	if (fstat(fd, &sb) == -1 || S_ISDIR(sb.st_mode)) {
		close(fd);
		return -3;
	}
	return fd;
}

static void *
xmalloc(size_t len)
{
	void *p;

	p = malloc(len);
	if (!p)
		err(1, "malloc %zu", len);
	return p;
}

static void
xfree(void *p, size_t len)
{
	if (!p)
		return;
	sodium_memzero(p, len);
	free(p);
}

void
reop_freestr(const char *str)
{
	xfree((void *)str, strlen(str));
}

/*
 * nacl wrapper functions.
 * the nacl API isn't very friendly, requiring the caller to provide padding
 * strange places. these functions workaround that by copying data, which is
 * generally how the nacl included c++ wrappers do things. the message data
 * is operated on separately from any required padding or nonce bytes.
 * wasteful, but convenient.
 * libsodium has actually solved most of these problems for us, but the above
 * comment remains to explain why we're not using the pure nacl interface.
 * the wrapper functions remain to enable us to go back to pure nacl (or any
 * other library) if that's ever desired. i'm trying not to wed the code to
 * any particular implementation.
 */

/*
 * wrapper around crypto_secretbox.
 * operates on buf "in place".
 */
static void
symencryptraw(uint8_t *buf, uint64_t buflen, uint8_t *nonce, uint8_t *tag, const uint8_t *symkey)
{
	randombytes(nonce, SYMNONCEBYTES);
	crypto_secretbox_detached(buf, tag, buf, buflen, nonce, symkey);
}

/*
 * wrapper around crypto_secretbox_open.
 * operates on buf "in place".
 */
static int
symdecryptraw(uint8_t *buf, uint64_t buflen, const uint8_t *nonce, const uint8_t *tag,
    const uint8_t *symkey)
{
	if (crypto_secretbox_open_detached(buf, buf, tag,
	    buflen, nonce, symkey) == -1)
		return -1;
	return 0;
}

/*
 * wrapper around crypto_box.
 * operates on buf "in place".
 */
static void
pubencryptraw(uint8_t *buf, uint64_t buflen, uint8_t *nonce, uint8_t *tag,
    const uint8_t *pubkey, const uint8_t *seckey)
{
	randombytes(nonce, ENCNONCEBYTES);
	crypto_box_detached(buf, tag, buf, buflen, nonce, pubkey, seckey);
}

/*
 * wrapper around crypto_box_open.
 * operates on buf "in place".
 */
static int
pubdecryptraw(uint8_t *buf, uint64_t buflen, const uint8_t *nonce, const uint8_t *tag,
    const uint8_t *pubkey, const uint8_t *seckey)
{
	if (crypto_box_open_detached(buf, buf, tag,
	    buflen, nonce, pubkey, seckey) == -1)
		return -1;
	return 0;
}

/*
 * wrapper around crypto_sign to generate detached signatures
 */
static void
signraw(const uint8_t *seckey, const uint8_t *buf, uint64_t buflen,
    uint8_t *sig)
{
	crypto_sign_detached(sig, NULL, buf, buflen, seckey);
}

/*
 * wrapper around crypto_sign_open supporting detached signatures
 */
static int
verifyraw(const uint8_t *pubkey, const uint8_t *buf, uint64_t buflen,
    const uint8_t *sig)
{
	if (crypto_sign_verify_detached(sig, buf, buflen, pubkey) == -1)
		return -1;
	return 0;
}

/* file utilities */
static int
readall(const char *filename, uint8_t **msgp, uint64_t *msglenp)
{
	struct stat sb;
	ssize_t x, space;
	const uint64_t maxmsgsize = 1UL << 30;
	int rv = -1;

	*msgp = NULL;
	*msglenp = 0;

	int fd = xopen(filename, O_RDONLY | O_NOFOLLOW, 0);
	if (fd == -1)
		return -1;
	if (fstat(fd, &sb) == 0 && S_ISREG(sb.st_mode)) {
		if (sb.st_size > maxmsgsize) {
			close(fd);
			return -2;
		}
		space = sb.st_size + 1;
	} else {
		space = 64 * 1024 - 1;
	}

	uint8_t *msg = malloc(space + 1);
	if (!msg) {
		close(fd);
		return -2;
	}
	uint64_t msglen = 0;
	while (1) {
		if (space == 0) {
			if (msglen * 2 > maxmsgsize) {
				rv = -2;
				goto fail;
			}
			space = msglen;
			uint8_t *newmsg;
			if (!(newmsg = realloc(msg, msglen + space + 1))) {
				rv = -2;
				goto fail;
			}
			msg = newmsg;
		}
		if ((x = read(fd, msg + msglen, space)) == -1) {
			rv = -3;
			goto fail;
		}
		if (x == 0)
			break;
		space -= x;
		msglen += x;
	}
	close(fd);

	msg[msglen] = 0;
	*msgp = msg;
	*msglenp = msglen;
	return 0;
fail:
	close(fd);
	free(msg);
	return rv;
}

/*
 * wrap lines in place.
 * start at the end and pull the string down as we go.
 */
static void
wraplines(char *str, size_t space)
{
	size_t len = strlen(str);
	size_t num = (len - 1) / 76;
	if (len + num + 1 > space)
		return;
	while (num > 0) {
		size_t pos = 76 * num - 1;
		size_t amt = len - pos < 76 ? len - pos : 76;
		memmove(str + pos + num, str + pos, amt + 1);
		str[pos + num] = '\n';
		num--;
	}
}

/*
 * create a filename based on user's home directory.
 * requires that ~/.reop exist.
 */
static int
gethomefile(const char *filename, char *buf, size_t buflen)
{
	struct stat sb;
	const char *home;

	if (!(home = getenv("HOME")))
		return -1;
	snprintf(buf, buflen, "%s/.reop", home);
	if (stat(buf, &sb) == -1 || !S_ISDIR(sb.st_mode))
		return -1;
	snprintf(buf, buflen, "%s/.reop/%s", home, filename);
	return 0;
}


/*
 * parse ident line, return pointer to next line
 */
static char *
readident(char *buf, char *ident)
{
#if IDENTLEN != 64
#error fix sscanf
#endif
	if (sscanf(buf, "ident:%63s", ident) != 1)
		errx(1, "no ident found: %s", buf);
	if (!(buf = strchr(buf + 1, '\n')))
		errx(1, "invalid header");
	return buf + 1;
}

/*
 * will parse a few different kinds of keys
 */
static int
parsekeydata(const char *keydataorig, const char *keytype, void *key, size_t keylen, char *ident)
{
	const char *beginkey = "-----BEGIN REOP ";
	const char *endkey = "-----END REOP ";

	char *keydata = strdup(keydataorig);
	if (strncmp(keydata, beginkey, strlen(beginkey)) != 0)
		goto invalid;
	if (strncmp(keydata + strlen(beginkey), keytype, strlen(keytype)) != 0)
		goto invalid;
	char *end;
	if (!(end = strstr(keydata, endkey)))
		goto invalid;
	*end = 0;
	char *begin;
	if (!(begin = strchr(keydata, '\n')))
		goto invalid;
	begin = readident(begin + 1, ident);
	*end = 0;
	if (reopb64_pton(begin, key, keylen) != keylen)
		errx(1, "invalid b64 encoding");

	xfree(keydata, strlen(keydata));

	return 0;

invalid:
	errx(1, "invalid key data");
	return -1; /* xxx */
}

/*
 * generate a symmetric encryption key.
 * caller creates and provides salt.
 * if rounds is 0 (no password requested), generates a dummy zero key.
 */
static void
kdf(const uint8_t *salt, size_t saltlen, int rounds, const char *password,
    kdf_confirm confirm, uint8_t *key, size_t keylen)
{
	if (rounds == 0) {
		memset(key, 0, keylen);
		return;
	}

	if (!password)
		password = getenv("REOP_PASSPHRASE");

	char passbuf[1024];
	if (!password) {
		int rppflags = RPP_REQUIRE_TTY | RPP_ECHO_OFF;
		if (!readpassphrase("passphrase: ", passbuf, sizeof(passbuf), rppflags))
			errx(1, "unable to read passphrase");
		if (strlen(passbuf) == 0)
			errx(1, "please provide a password");
		if (confirm.v) {
			char pass2[1024];

			if (!readpassphrase("confirm passphrase: ", pass2,
			    sizeof(pass2), rppflags))
				errx(1, "unable to read passphrase");
			if (strcmp(passbuf, pass2) != 0)
				errx(1, "passwords don't match");
			sodium_memzero(pass2, sizeof(pass2));
		}
		password = passbuf;
	}
	if (bcrypt_pbkdf(password, strlen(password), salt, saltlen, key,
	    keylen, rounds) == -1)
		errx(1, "bcrypt pbkdf");
	sodium_memzero(passbuf, sizeof(passbuf));
}

/*
 * secret keys are themselves encrypted before export to string format.
 * they must be decrypted before use. even zero round keys (empty password)
 * are still encrypted with a null key.
 * these functions will prompt for password if none is provided.
 */
static void
encryptseckey(struct reop_seckey *seckey, const char *password)
{
	uint8_t symkey[SYMKEYBYTES];
	kdf_confirm confirm = { 1 };

	int rounds = 42;
	if (password && strlen(password) == 0)
		rounds = 0;

	randombytes(seckey->salt, sizeof(seckey->salt));
	seckey->kdfrounds = htonl(rounds);

	kdf(seckey->salt, sizeof(seckey->salt), rounds, password,
	    confirm, symkey, sizeof(symkey));
	symencryptraw(seckey->sigkey, sizeof(seckey->sigkey) + sizeof(seckey->enckey),
	    seckey->nonce, seckey->tag, symkey);
	sodium_memzero(symkey, sizeof(symkey));
}

static int
decryptseckey(struct reop_seckey *seckey, const char *password)
{
	if (memcmp(seckey->kdfalg, KDFALG, 2) != 0)
		return -2;

	uint8_t symkey[SYMKEYBYTES];
	kdf_confirm confirm = { 0 };

	int rounds = ntohl(seckey->kdfrounds);

	kdf(seckey->salt, sizeof(seckey->salt), rounds, password,
	    confirm, symkey, sizeof(symkey));
	int rv = symdecryptraw(seckey->sigkey, sizeof(seckey->sigkey) + sizeof(seckey->enckey),
	    seckey->nonce, seckey->tag, symkey);
	sodium_memzero(symkey, sizeof(symkey));
	if (rv != 0)
		return rv;

	return 0;
}

/*
 * read user's pubkeyring file to allow lookup by ident
 * blank lines are permitted between keys, but not within
 */
static int
findpubkey(const char *ident, struct reop_pubkey *key)
{
	const char *beginkey = "-----BEGIN REOP PUBLIC KEY-----\n";
	const char *endkey = "-----END REOP PUBLIC KEY-----\n";

	char keyringname[1024];
	if (gethomefile("pubkeyring", keyringname, sizeof(keyringname)) != 0)
		return -1;
	FILE *fp = fopen(keyringname, "r");
	if (!fp)
		return -1;

	char line[1024];
	while (fgets(line, sizeof(line), fp)) {
		char buf[1024];
		buf[0] = 0;
		int identline = 1;
		if (line[0] == 0 || line[0] == '\n')
			continue;
		if (strncmp(line, beginkey, strlen(beginkey)) != 0)
			goto fail;
		char identbuf[IDENTLEN];
		while (1) {
			if (!fgets(line, sizeof(line), fp))
				goto fail;
			if (identline) {
				readident(line, identbuf);
				identline = 0;
				continue;
			}
			if (strncmp(line, endkey, strlen(endkey)) == 0)
				break;
			strlcat(buf, line, sizeof(buf));
		}
		if (strcmp(ident, identbuf) == 0) {
			strlcpy(key->ident, identbuf, sizeof(key->ident));
			if (reopb64_pton(buf, (void *)key, pubkeysize) != pubkeysize)
				goto fail;
			fclose(fp);
			return 0;
		}
	}
fail:
	fclose(fp);
	return -1;
}

/*
 * 1. specified file
 * 2. lookup ident
 * 3. default pubkey file
 */
const struct reop_pubkey *
reop_getpubkey(const char *pubkeyfile, const char *ident)
{
	struct reop_pubkey *pubkey = malloc(sizeof(*pubkey));
	if (!pubkey)
		return NULL;

	if (!pubkeyfile && ident) {
		if (findpubkey(ident, pubkey) == 0)
			return pubkey;
		goto fail;
	}
	char namebuf[1024];
	if (!pubkeyfile && gethomefile("pubkey", namebuf, sizeof(namebuf)) == 0)
		pubkeyfile = namebuf;
	if (!pubkeyfile)
		goto fail;

	uint64_t keydatalen;
	uint8_t *keydata;
	readall(pubkeyfile, &keydata, &keydatalen);
	if (!keydata)
		goto fail;
	int rv = parsekeydata(keydata, "PUBLIC KEY", pubkey, pubkeysize, pubkey->ident);
	xfree(keydata, keydatalen);
	if (rv != 0)
		goto fail;
	return pubkey;

fail:
	free(pubkey);
	return NULL;
}

/*
 * free pubkey
 */
void
reop_freepubkey(const struct reop_pubkey *pubkey)
{
	xfree((void *)pubkey, sizeof(*pubkey));
}

/*
 * 1. specified file
 * 2. default seckey file
 */
const struct reop_seckey *
reop_getseckey(const char *seckeyfile, const char *password)
{
	struct reop_seckey *seckey = malloc(sizeof(*seckey));
	if (!seckey)
		return NULL;

	char namebuf[1024];
	if (!seckeyfile && gethomefile("seckey", namebuf, sizeof(namebuf)) == 0)
		seckeyfile = namebuf;
	if (!seckeyfile)
		goto fail;

	uint64_t keydatalen;
	uint8_t *keydata;
	readall(seckeyfile, &keydata, &keydatalen);
	if (!keydata)
		goto fail;
	int rv = parsekeydata(keydata, "SECRET KEY", seckey, seckeysize, seckey->ident);
	xfree(keydata, keydatalen);
	if (rv != 0)
		goto fail;
	rv = decryptseckey(seckey, password);
	if (rv != 0)
		goto fail;
	return seckey;

fail:
	xfree(seckey, sizeof(*seckey));
	return NULL;
}

/*
 * free seckey
 */
void
reop_freeseckey(const struct reop_seckey *seckey)
{
	xfree((void *)seckey, sizeof(*seckey));
}

/*
 * can write a few different file types
 */
static const char *
encodekey(const char *info, const void *key, size_t keylen, const char *ident)
{
	char buf[1024];
	char b64[1024];

	if (reopb64_ntop(key, keylen, b64, sizeof(b64)) == -1)
		errx(1, "b64 encode failed");
	wraplines(b64, sizeof(b64));
	snprintf(buf, sizeof(buf), "-----BEGIN REOP %s-----\n"
	    "ident:%s\n"
	    "%s\n"
	    "-----END REOP %s-----\n",
	    info, ident, b64, info);
	char *str = strdup(buf);
	sodium_memzero(b64, sizeof(b64));
	sodium_memzero(buf, sizeof(buf));
	return str;
}

/*
 * generate a complete key pair (actually two, for signing and encryption)
 */
struct reop_keypair
reop_generate(const char *ident)
{
	uint8_t randomid[RANDOMIDLEN];

	struct reop_pubkey *pubkey = xmalloc(sizeof(*pubkey));
	memset(pubkey, 0, sizeof(*pubkey));

	struct reop_seckey *seckey = xmalloc(sizeof(*seckey));
	memset(seckey, 0, sizeof(*seckey));

	strlcpy(pubkey->ident, ident, sizeof(pubkey->ident));
	strlcpy(seckey->ident, ident, sizeof(seckey->ident));

	crypto_sign_ed25519_keypair(pubkey->sigkey, seckey->sigkey);
	crypto_box_keypair(pubkey->enckey, seckey->enckey);
	randombytes(randomid, sizeof(randomid));

	memcpy(seckey->randomid, randomid, RANDOMIDLEN);
	memcpy(seckey->sigalg, SIGALG, 2);
	memcpy(seckey->encalg, ENCKEYALG, 2);
	memcpy(seckey->symalg, SYMALG, 2);
	memcpy(seckey->kdfalg, KDFALG, 2);

	memcpy(pubkey->randomid, randomid, RANDOMIDLEN);
	memcpy(pubkey->sigalg, SIGALG, 2);
	memcpy(pubkey->encalg, ENCKEYALG, 2);

	struct reop_keypair keypair = { pubkey, seckey };
	return keypair;
}

/*
 * parse pubkey data into struct
 */
const struct reop_pubkey *
reop_parsepubkey(const char *pubkeydata)
{
	struct reop_pubkey *pubkey = xmalloc(sizeof(*pubkey));
	parsekeydata(pubkeydata, "PUBLIC KEY", pubkey, pubkeysize, pubkey->ident);
	return pubkey;
}

/*
 * encode a pubkey to a string
 */
const char *
reop_encodepubkey(const struct reop_pubkey *pubkey)
{
	return encodekey("PUBLIC KEY", pubkey, pubkeysize, pubkey->ident);
}

/*
 * parse seckey data into struct
 */
const struct reop_seckey *
reop_parseseckey(const char *seckeydata, const char *password)
{
	struct reop_seckey *seckey = xmalloc(sizeof(*seckey));
	parsekeydata(seckeydata, "SECRET KEY", seckey, seckeysize, seckey->ident);

	int rv = decryptseckey(seckey, password);
	if (rv != 0) {
		xfree(seckey, sizeof(*seckey));
		return NULL;
	}
	return seckey;
}

/*
 * encode a seckey to a string
 */
const char *
reop_encodeseckey(const struct reop_seckey *seckey, const char *password)
{
	struct reop_seckey copy = *seckey;
	encryptseckey(&copy, password);
	const char *rv = encodekey("SECRET KEY", &copy, seckeysize, seckey->ident);
	sodium_memzero(&copy, sizeof(copy));
	return rv;
}

/*
 * basic sign function
 */
const struct reop_sig *
reop_sign(const struct reop_seckey *seckey, const uint8_t *msg, uint64_t msglen)
{
	struct reop_sig *sig = xmalloc(sizeof(*sig));

	signraw(seckey->sigkey, msg, msglen, sig->sig);

	memcpy(sig->randomid, seckey->randomid, RANDOMIDLEN);
	memcpy(sig->sigalg, SIGALG, 2);
	strlcpy(sig->ident, seckey->ident, sizeof(sig->ident));

	return sig;
}

/*
 * free sig
 */
void
reop_freesig(const struct reop_sig *sig)
{
	xfree((void *)sig, sizeof(*sig));
}

/*
 * parse signature data into struct
 */
const struct reop_sig *
reop_parsesig(const char *sigdata)
{
	struct reop_sig *sig = xmalloc(sizeof(*sig));
	parsekeydata(sigdata, "SIGNATURE", sig, sigsize, sig->ident);
	return sig;
}

/*
 * encode a signature to a string
 */
const char *
reop_encodesig(const struct reop_sig *sig)
{
	return encodekey("SIGNATURE", sig, sigsize, sig->ident);
}

/*
 * basic verify function
 */
reop_verify_result
reop_verify(const struct reop_pubkey *pubkey, const uint8_t *msg, uint64_t msglen,
    const struct reop_sig *sig)
{
	if (memcmp(pubkey->randomid, sig->randomid, RANDOMIDLEN) != 0)
		return (reop_verify_result) { REOP_V_MISMATCH };

	if (verifyraw(pubkey->sigkey, msg, msglen, sig->sig) == -1)
		return (reop_verify_result) { REOP_V_FAIL };

	return (reop_verify_result) { REOP_V_OK };
}

/*
 * encrypt a file using public key cryptography
 * an ephemeral key is used to make the encryption one way
 * that key is then encrypted with our seckey to provide authentication
 */
const struct reop_encmsg *
reop_pubencrypt(const struct reop_pubkey *pubkey, const struct reop_seckey *seckey,
    uint8_t *msg, uint64_t msglen)
{
	struct reop_encmsg *encmsg = malloc(sizeof(*encmsg));
	if (!encmsg)
		return NULL;

	memcpy(encmsg->encalg, ENCALG, 2);
	memcpy(encmsg->pubrandomid, pubkey->randomid, RANDOMIDLEN);
	memcpy(encmsg->secrandomid, seckey->randomid, RANDOMIDLEN);

	uint8_t ephseckey[ENCSECRETBYTES];
	crypto_box_keypair(encmsg->ephpubkey, ephseckey);
	strlcpy(encmsg->ident, seckey->ident, sizeof(encmsg->ident));

	pubencryptraw(msg, msglen, encmsg->nonce, encmsg->tag, pubkey->enckey, ephseckey);
	pubencryptraw(encmsg->ephpubkey, sizeof(encmsg->ephpubkey), encmsg->ephnonce,
	    encmsg->ephtag, pubkey->enckey, seckey->enckey);

	sodium_memzero(&ephseckey, sizeof(ephseckey));

	return encmsg;
}

reop_decrypt_result
reop_pubdecrypt(const struct reop_encmsg *encmsg, const struct reop_pubkey *pubkey,
    const struct reop_seckey *seckey, uint8_t *msg, uint64_t msglen)
{
	if (memcmp(encmsg->pubrandomid, seckey->randomid, RANDOMIDLEN) != 0 ||
	    memcmp(encmsg->secrandomid, pubkey->randomid, RANDOMIDLEN) != 0)
		return (reop_decrypt_result) { REOP_D_MISMATCH };

	if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
		return (reop_decrypt_result) { REOP_D_INVALID };
	if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
		return (reop_decrypt_result) { REOP_D_INVALID };

	uint8_t ephpubkey[ENCPUBLICBYTES];
	memcpy(ephpubkey, encmsg->ephpubkey, sizeof(encmsg->ephpubkey));
	int rv = pubdecryptraw(ephpubkey, sizeof(ephpubkey),
	    encmsg->ephnonce, encmsg->ephtag, pubkey->enckey, seckey->enckey);
	if (rv != 0)
		return (reop_decrypt_result) { REOP_D_FAIL };

	rv = pubdecryptraw(msg, msglen, encmsg->nonce, encmsg->tag,
	    ephpubkey, seckey->enckey);
	if (rv != 0)
		return (reop_decrypt_result) { REOP_D_FAIL };

	sodium_memzero(ephpubkey, sizeof(ephpubkey));

	return (reop_decrypt_result) { 0 };
}

reop_decrypt_result
reop_symdecrypt(const struct reop_symmsg *symmsg, const char *password, uint8_t *msg,
    uint64_t msglen)
{
	if (memcmp(symmsg->kdfalg, KDFALG, 2) != 0)
		return (reop_decrypt_result) { REOP_D_INVALID };

	kdf_confirm confirm = { 0 };
	int rounds = ntohl(symmsg->kdfrounds);
	uint8_t symkey[SYMKEYBYTES];
	kdf(symmsg->salt, sizeof(symmsg->salt), rounds, NULL,
	    confirm, symkey, sizeof(symkey));

	int rv = symdecryptraw(msg, msglen, symmsg->nonce, symmsg->tag, symkey);
	if (rv != 0)
		return (reop_decrypt_result) { REOP_D_FAIL };

	sodium_memzero(symkey, sizeof(symkey));

	return (reop_decrypt_result) { 0 };
}

void
reop_freeencmsg(const struct reop_encmsg *encmsg)
{
	xfree((void *)encmsg, sizeof(*encmsg));
}

/*
 * encrypt a message using symmetric cryptography (a password)
 */
const struct reop_symmsg *
reop_symencrypt(uint8_t *msg, uint64_t msglen, const char *password)
{
	struct reop_symmsg *symmsg = malloc(sizeof(*symmsg));
	if (!symmsg)
		return NULL;

	int rounds = 42;

	memcpy(symmsg->symalg, SYMALG, 2);
	memcpy(symmsg->kdfalg, KDFALG, 2);
	symmsg->kdfrounds = htonl(rounds);
	randombytes(symmsg->salt, sizeof(symmsg->salt));

	uint8_t symkey[SYMKEYBYTES];
	kdf_confirm confirm = { 1 };
	kdf(symmsg->salt, sizeof(symmsg->salt), rounds, password,
	    confirm, symkey, sizeof(symkey));

	symencryptraw(msg, msglen, symmsg->nonce, symmsg->tag, symkey);

	sodium_memzero(symkey, sizeof(symkey));

	return symmsg;
}

void
reop_freesymmsg(const struct reop_symmsg *symmsg)
{
	xfree((void *)symmsg, sizeof(*symmsg));
}

void
reop_init(void)
{
	sodium_init();
}

#ifdef REOPMAIN

static int
xopenorfail(const char *filename, int oflags, mode_t mode)
{
	int fd = xopen(filename, oflags, mode);
	if (fd >= 0)
		return fd;
	switch (fd) {
	case -1:
		err(1, "can't open %s for %s", filename,
		    (oflags & O_WRONLY) ? "writing" : "reading");
		break;
	case -2:
		err(1, "dup failed");
		break;
	case -3:
		errx(1, "not a valid file: %s", filename);
		break;
	default:
		errx(1, "can't open %s", filename);
		break;
	}
	return -1;
}

static void
readallorfail(const char *filename, uint8_t **msgp, uint64_t *msglenp)
{
	int rv = readall(filename, msgp, msglenp);
	switch (rv) {
	case 0:
		break;
	case -1:
		err(1, "could not open %s", filename);
		break;
	case -2:
		errx(1, "%s is too large", filename);
		break;
	default:
		errx(1, "could not read %s", filename);
		break;
	}
}

static void
writeall(int fd, const void *buf, size_t buflen, const char *filename)
{
	while (buflen != 0) {
		ssize_t x = write(fd, buf, buflen);
		if (x == -1)
			err(1, "write to %s", filename);
		buflen -= x;
		buf = (char *)buf + x;
	}
}

/*
 * can really write any kind of data, but we're usually interested in line
 * wrapping for base64 encoded blocks
 */
static void
writeb64data(int fd, const char *filename, char *b64)
{
	size_t rem = strlen(b64);
	size_t pos = 0;
	while (rem > 0) {
		size_t amt = rem > 76 ? 76 : rem;
		writeall(fd, b64 + pos, amt, filename);
		writeall(fd, "\n", 1, filename);
		pos += amt;
		rem -= amt;
	}
}

static void
generate(const char *pubkeyfile, const char *seckeyfile, const char *ident,
    const char *password)
{
	struct reop_keypair keypair = reop_generate(ident);

	char secnamebuf[1024];
	if (!seckeyfile && gethomefile("seckey", secnamebuf, sizeof(secnamebuf)) == 0)
		seckeyfile = secnamebuf;
	if (!seckeyfile)
		errx(1, "no seckeyfile");

	int fd = xopenorfail(seckeyfile, O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY, 0600);
	const char *keydata = reop_encodeseckey(keypair.seckey, password);
	writeall(fd, keydata, strlen(keydata), seckeyfile);
	reop_freestr(keydata);
	close(fd);


	char pubnamebuf[1024];
	if (!pubkeyfile && gethomefile("pubkey", pubnamebuf, sizeof(pubnamebuf)) == 0)
		pubkeyfile = pubnamebuf;
	if (!pubkeyfile)
		errx(1, "no pubkeyfile");

	fd = xopenorfail(pubkeyfile, O_CREAT|O_EXCL|O_NOFOLLOW|O_WRONLY, 0666);
	keydata = reop_encodepubkey(keypair.pubkey);
	writeall(fd, keydata, strlen(keydata), pubkeyfile);
	reop_freestr(keydata);
	close(fd);

	reop_freepubkey(keypair.pubkey);
	reop_freeseckey(keypair.seckey);
}

/*
 * write a combined message and signature
 */
static void
writesignedmsg(const char *filename, const struct reop_sig *sig,
    const char *ident, const uint8_t *msg, uint64_t msglen)
{
	char header[1024];
	char b64[1024];

	int fd = xopenorfail(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
	snprintf(header, sizeof(header), "-----BEGIN REOP SIGNED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	writeall(fd, msg, msglen, filename);

	snprintf(header, sizeof(header), "-----BEGIN REOP SIGNATURE-----\n"
	    "ident:%s\n", ident);
	writeall(fd, header, strlen(header), filename);
	if (reopb64_ntop((void *)sig, sigsize, b64, sizeof(b64)) == -1)
		errx(1, "b64 encode failed");
	writeb64data(fd, filename, b64);
	sodium_memzero(b64, sizeof(b64));
	snprintf(header, sizeof(header), "-----END REOP SIGNED MESSAGE-----\n");
	writeall(fd, header, strlen(header), filename);
	close(fd);
}

/*
 * sign a file
 */
static void
signfile(const char *seckeyfile, const char *msgfile, const char *sigfile,
    int embedded)
{
	uint64_t msglen;
	uint8_t *msg;
	readallorfail(msgfile, &msg, &msglen);

	const struct reop_seckey *seckey = reop_getseckey(seckeyfile, NULL);
	if (!seckey)
		errx(1, "no seckey");

	const struct reop_sig *sig = reop_sign(seckey, msg, msglen);

	reop_freeseckey(seckey);

	if (embedded)
		writesignedmsg(sigfile, sig, sig->ident, msg, msglen);
	else {
		int fd = xopenorfail(sigfile, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
		const char *sigdata = reop_encodesig(sig);
		writeall(fd, sigdata, strlen(sigdata), sigfile);
		reop_freestr(sigdata);
		close(fd);
	}

	reop_freesig(sig);
	xfree(msg, msglen);
}

/*
 * read signature file
 */
static const struct reop_sig *
readsigfile(const char *sigfile)
{
	uint64_t sigdatalen;
	uint8_t *sigdata;
	readall(sigfile, &sigdata, &sigdatalen);
	if (!sigdata)
		errx(1, "could not read %s", sigfile);
	const struct reop_sig *sig = reop_parsesig(sigdata);
	xfree(sigdata, sigdatalen);
	return sig;
}

/*
 * simple case, detached signature
 */
static void
verifysimple(const char *pubkeyfile, const char *msgfile, const char *sigfile,
    int quiet)
{
	uint64_t msglen;
	uint8_t *msg;
	readallorfail(msgfile, &msg, &msglen);

	const struct reop_sig *sig = readsigfile(sigfile);
	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, sig->ident);
	if (!pubkey)
		errx(1, "no pubkey");

	reop_verify_result rv = reop_verify(pubkey, msg, msglen, sig);
	switch (rv.v) {
	case REOP_V_OK:
		if (!quiet)
			printf("Signature Verified\n");
		break;
	case REOP_V_MISMATCH:
		errx(1, "verification failed: checked against wrong key");
	default:
		errx(1, "signature verification failed");
	}

	reop_freesig(sig);
	reop_freepubkey(pubkey);
	xfree(msg, msglen);
}

/*
 * message followed by signature in one file
 */
static void
verifyembedded(const char *pubkeyfile, const char *sigfile, int quiet)
{
	const char *beginmsg = "-----BEGIN REOP SIGNED MESSAGE-----\n";
	const char *beginsig = "-----BEGIN REOP SIGNATURE-----\n";

	uint64_t msgdatalen;
	uint8_t *msgdata;
	readallorfail(sigfile, &msgdata, &msgdatalen);

	if (strncmp(msgdata, beginmsg, strlen(beginmsg)) != 0)
 		goto fail;
	char *msg = msgdata + 36;
	char *sigdata, *nextsig;
	if (!(sigdata = strstr(msg, beginsig)))
 		goto fail;
	while ((nextsig = strstr(sigdata + 1, beginsig)))
		sigdata = nextsig;
	uint64_t msglen = sigdata - msg;

	const struct reop_sig *sig = reop_parsesig(sigdata);
	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, sig->ident);
	if (!pubkey)
		errx(1, "no pubkey");

	reop_verify_result rv = reop_verify(pubkey, (uint8_t *)msg, msglen, sig);
	switch (rv.v) {
	case REOP_V_OK:
		if (!quiet)
			printf("Signature Verified\n");
		break;
	case REOP_V_MISMATCH:
		errx(1, "verification failed: checked against wrong key");
	default:
		errx(1, "signature verification failed");
	}

	reop_freesig(sig);
	reop_freepubkey(pubkey);
	xfree(msgdata, msgdatalen);

	return;
fail:
	errx(1, "invalid signature: %s", sigfile);
}

/*
 * write an reop encrypted message header, followed by base64 data
 */
static void
writeencfile(const char *filename, const void *hdr,
    size_t hdrlen, const char *ident, uint8_t *msg, uint64_t msglen,
    opt_binary binary)
{
	if (binary.v) {
		uint32_t identlen = strlen(ident);
		identlen = htonl(identlen);

		int fd = xopenorfail(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);

		writeall(fd, REOP_BINARY, 4, filename);
		writeall(fd, hdr, hdrlen, filename);
		writeall(fd, &identlen, sizeof(identlen), filename);
		writeall(fd, ident, strlen(ident), filename);
		writeall(fd, msg, msglen, filename);
		close(fd);
	} else {
		char header[1024];
		char b64[1024];

		size_t b64len = (msglen + 2) / 3 * 4 + 1;
		char *b64data = xmalloc(b64len);
		if (reopb64_ntop(msg, msglen, b64data, b64len) == -1)
			errx(1, "b64 encode failed");

		int fd = xopenorfail(filename, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
		snprintf(header, sizeof(header), "-----BEGIN REOP ENCRYPTED MESSAGE-----\n");
		writeall(fd, header, strlen(header), filename);
		snprintf(header, sizeof(header), "ident:%s\n", ident);
		writeall(fd, header, strlen(header), filename);
		if (reopb64_ntop(hdr, hdrlen, b64, sizeof(b64)) == -1)
			errx(1, "b64 encode failed");
		writeb64data(fd, filename, b64);
		sodium_memzero(b64, sizeof(b64));

		snprintf(header, sizeof(header), "-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n");
		writeall(fd, header, strlen(header), filename);
		writeb64data(fd, filename, b64data);
		xfree(b64data, b64len);

		snprintf(header, sizeof(header), "-----END REOP ENCRYPTED MESSAGE-----\n");
		writeall(fd, header, strlen(header), filename);
		close(fd);
	}
}

/*
 * encrypt a file using public key cryptography
 * an ephemeral key is used to make the encryption one way
 * that key is then encrypted with our seckey to provide authentication
 */
static void
pubencrypt(const char *pubkeyfile, const char *ident, const char *seckeyfile,
    const char *msgfile, const char *encfile, opt_binary binary)
{
	uint64_t msglen;
	uint8_t *msg;
	readallorfail(msgfile, &msg, &msglen);

	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
	if (!pubkey)
		errx(1, "no pubkey");
	const struct reop_seckey *seckey = reop_getseckey(seckeyfile, NULL);
	if (!seckey)
		errx(1, "no seckey");

	if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");
	if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");

	const struct reop_encmsg *encmsg = reop_pubencrypt(pubkey, seckey, msg, msglen);
	reop_freeseckey(seckey);
	reop_freepubkey(pubkey);

	writeencfile(encfile, encmsg, encmsgsize, encmsg->ident, msg, msglen, binary);

	reop_freeencmsg(encmsg);

	xfree(msg, msglen);
}

/*
 * encrypt a file using public key cryptography
 * old version 1.0 variant
 */
static void
v1pubencrypt(const char *pubkeyfile, const char *ident, const char *seckeyfile,
    const char *msgfile, const char *encfile, opt_binary binary)
{
	struct oldencmsg oldencmsg;

	const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
	if (!pubkey)
		errx(1, "no pubkey");
	const struct reop_seckey *seckey = reop_getseckey(seckeyfile, NULL);
	if (!seckey)
		errx(1, "no seckey");

	uint64_t msglen;
	uint8_t *msg;
	readallorfail(msgfile, &msg, &msglen);

	if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");
	if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
		errx(1, "unsupported key format");
	memcpy(oldencmsg.encalg, OLDENCALG, 2);
	memcpy(oldencmsg.pubrandomid, pubkey->randomid, RANDOMIDLEN);
	memcpy(oldencmsg.secrandomid, seckey->randomid, RANDOMIDLEN);
	pubencryptraw(msg, msglen, oldencmsg.nonce, oldencmsg.tag, pubkey->enckey,
	    seckey->enckey);

	writeencfile(encfile, &oldencmsg, sizeof(oldencmsg), seckey->ident, msg, msglen, binary);

	reop_freeseckey(seckey);
	reop_freepubkey(pubkey);

	xfree(msg, msglen);
}

static void
symencrypt(const char *msgfile, const char *encfile, opt_binary binary)
{
	uint64_t msglen;
	uint8_t *msg;
	readallorfail(msgfile, &msg, &msglen);

	const struct reop_symmsg *symmsg = reop_symencrypt(msg, msglen, NULL);
	if (!symmsg)
		errx(1, "encrypt failed");

	writeencfile(encfile, symmsg, symmsgsize, "<symmetric>", msg, msglen, binary);

	reop_freesymmsg(symmsg);

	xfree(msg, msglen);
}

/*
 * decrypt a file, either public key or symmetric based on header
 */
static void
decrypt(const char *pubkeyfile, const char *seckeyfile, const char *msgfile,
    const char *encfile)
{
	char ident[IDENTLEN];
	uint8_t *msg;
	uint64_t msglen;
	union {
		uint8_t alg[2];
		struct reop_symmsg symmsg;
		struct reop_encmsg encmsg;
		struct oldencmsg oldencmsg;
		struct oldekcmsg oldekcmsg;
	} hdr;
	int hdrsize;

	uint64_t encdatalen;
	uint8_t *encdata;
	readallorfail(encfile, &encdata, &encdatalen);

	if (encdatalen >= 6 && memcmp(encdata, REOP_BINARY, 4) == 0) {
		uint8_t *ptr = encdata + 4;
		uint8_t *endptr = encdata + encdatalen;
		uint32_t identlen;

		if (memcmp(ptr, SYMALG, 2) == 0) {
			hdrsize = symmsgsize;
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.symmsg, ptr, hdrsize);
			ptr += hdrsize;
		} else if (memcmp(ptr, ENCALG, 2) == 0) {
			hdrsize = encmsgsize;
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.encmsg, ptr, hdrsize);
			ptr += hdrsize;
		} else if (memcmp(ptr, OLDENCALG, 2) == 0) {
			hdrsize = sizeof(hdr.oldencmsg);
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.oldencmsg, ptr, hdrsize);
			ptr += hdrsize;
		} else if (memcmp(ptr, OLDEKCALG, 2) == 0) {
			hdrsize = sizeof(hdr.oldekcmsg);
			if (ptr + hdrsize > endptr)
				goto fail;
			memcpy(&hdr.oldekcmsg, ptr, hdrsize);
			ptr += hdrsize;
		} else {
			goto fail;
		}
		if (ptr + sizeof(identlen) > endptr)
			goto fail;
		memcpy(&identlen, ptr, sizeof(identlen));
		ptr += sizeof(identlen);
		identlen = ntohl(identlen);
		if (identlen >= sizeof(ident))
			goto fail;
		if (ptr + identlen > endptr)
			goto fail;
		memcpy(ident, ptr, identlen);
		ident[identlen] = '\0';
		ptr += identlen;
		msg = ptr;
		msglen = endptr - ptr;
	} else {
		char *begin, *end;
		const char *beginmsg = "-----BEGIN REOP ENCRYPTED MESSAGE-----\n";
		const char *begindata = "-----BEGIN REOP ENCRYPTED MESSAGE DATA-----\n";
		const char *endmsg = "-----END REOP ENCRYPTED MESSAGE-----\n";

		if (strncmp(encdata, beginmsg, strlen(beginmsg)) != 0)
			goto fail;
		begin = readident(encdata + strlen(beginmsg), ident);
		if (!(end = strstr(begin, begindata)))
			goto fail;
		*end = 0;
		if ((hdrsize = reopb64_pton(begin, (void *)&hdr, sizeof(hdr))) == -1)
			goto fail;
		begin = end + strlen(begindata);
		if (!(end = strstr(begin, endmsg)))
			goto fail;
		*end = 0;

		msglen = (strlen(begin) + 3) / 4 * 3 + 1;
		msg = xmalloc(msglen);
		msglen = reopb64_pton(begin, msg, msglen);
		if (msglen == -1)
			goto fail;
		xfree(encdata, encdatalen);
		encdata = NULL;
	}

	if (memcmp(hdr.alg, SYMALG, 2) == 0) {
		if (hdrsize != symmsgsize)
			goto fail;

		reop_decrypt_result rv = reop_symdecrypt(&hdr.symmsg, NULL, msg, msglen);
		switch (rv.v) {
		case REOP_D_OK:
			break;
		case REOP_D_FAIL:
			errx(1, "sym decryption failed");
			break;
		case REOP_D_INVALID:
			errx(1, "unsupported key format");
			break;
		default:
			errx(1, "sym decryption failed");
			break;
		}

	} else if (memcmp(hdr.alg, ENCALG, 2) == 0) {
		if (hdrsize != encmsgsize)
			goto fail;
		const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
		if (!pubkey)
			errx(1, "no pubkey");
		const struct reop_seckey *seckey = reop_getseckey(seckeyfile, NULL);
		if (!seckey)
			errx(1, "no seckey");

		reop_decrypt_result rv = reop_pubdecrypt(&hdr.encmsg, pubkey, seckey, msg, msglen);
		switch (rv.v) {
		case REOP_D_OK:
			break;
		case REOP_D_FAIL:
			errx(1, "pub decryption failed");
			break;
		case REOP_D_MISMATCH:
			errx(1, "key mismatch");
			break;
		case REOP_D_INVALID:
			errx(1, "unsupported key format");
			break;
		default:
			errx(1, "pub decryption failed");
			break;
		}

		reop_freeseckey(seckey);
		reop_freepubkey(pubkey);
	} else if (memcmp(hdr.alg, OLDENCALG, 2) == 0) {
		if (hdrsize != sizeof(hdr.oldencmsg))
			goto fail;
		const struct reop_pubkey *pubkey = reop_getpubkey(pubkeyfile, ident);
		if (!pubkey)
			errx(1, "no pubkey");
		const struct reop_seckey *seckey = reop_getseckey(seckeyfile, NULL);
		if (!seckey)
			errx(1, "no seckey");
		/* pub/sec pairs work both ways */
		if (memcmp(hdr.oldencmsg.pubrandomid, pubkey->randomid, RANDOMIDLEN) == 0) {
			if (memcmp(hdr.oldencmsg.secrandomid, seckey->randomid, RANDOMIDLEN) != 0)
				goto fpfail;
		} else if (memcmp(hdr.oldencmsg.pubrandomid, seckey->randomid, RANDOMIDLEN) != 0 ||
		    memcmp(hdr.oldencmsg.pubrandomid, seckey->randomid, RANDOMIDLEN) != 0)
			goto fpfail;

		if (memcmp(pubkey->encalg, ENCKEYALG, 2) != 0)
			errx(1, "unsupported key format");
		if (memcmp(seckey->encalg, ENCKEYALG, 2) != 0)
			errx(1, "unsupported key format");
		int rv = pubdecryptraw(msg, msglen, hdr.oldencmsg.nonce, hdr.oldencmsg.tag,
		    pubkey->enckey, seckey->enckey);
		if (rv != 0)
			errx(1, "pub decryption failed");
		reop_freeseckey(seckey);
		reop_freepubkey(pubkey);
	} else if (memcmp(hdr.alg, OLDEKCALG, 2) == 0) {
		if (hdrsize != sizeof(hdr.oldekcmsg))
			goto fail;
		const struct reop_seckey *seckey = reop_getseckey(seckeyfile, NULL);
		if (!seckey)
			errx(1, "no seckey");
		if (memcmp(hdr.oldekcmsg.pubrandomid, seckey->randomid, RANDOMIDLEN) != 0)
			goto fpfail;

		int rv = pubdecryptraw(msg, msglen, hdr.oldekcmsg.nonce, hdr.oldekcmsg.tag,
		    hdr.oldekcmsg.pubkey, seckey->enckey);
		if (rv != 0)
			errx(1, "pub decryption failed");
		reop_freeseckey(seckey);
	} else {
		goto fail;
	}
	int fd = xopenorfail(msgfile, O_CREAT|O_TRUNC|O_NOFOLLOW|O_WRONLY, 0666);
	writeall(fd, msg, msglen, msgfile);
	close(fd);
	/*
	 * if encdata is not null, it is the original data read in.
	 * msg points into encdata (don't free).
	 * otherwise encdata was freed when it was base64 decoded into msg.
	 * in this case, free msg.
	 */
	if (encdata)
		xfree(encdata, encdatalen);
	else
		xfree(msg, msglen);
	return;

fail:
	errx(1, "invalid encrypted message: %s", encfile);
fpfail:
	errx(1, "key mismatch");
}

static void
usage(const char *error)
{
	if (error)
		fprintf(stderr, "%s\n", error);
	fprintf(stderr, "Usage:\n"
"\treop -G [-n] [-i identity] [-p public-key-file -s secret-key-file]\n"
"\treop -D [-i identity] [-p public-key-file -s secret-key-file]\n"
"\t\t-m message-file [-x ciphertext-file]\n"
"\treop -E [-1b] [-i identity] [-p public-key-file -s secret-key-file]\n"
"\t\t-m message-file [-x ciphertext-file]\n"
"\treop -S [-e] [-x signature-file] -s secret-key-file -m message-file\n"
"\treop -V [-eq] [-x signature-file] -p public-key-file -m message-file\n"
	    );
	exit(1);
}

#if 0
static void
agentserver(const char *sockname, const char *seckeyfile)
{
	const struct reop_seckey *seckey = reop_getseckey(seckeyfile, NULL);
	if (!seckey)
		errx(1, "unable to open seckey");
	const char *keydata = reop_encodeseckey(seckey, "");
	if (!keydata)
		errx(1, "unable to encode seckey");

	struct sockaddr_un sa;
	memset(&sa, 0, sizeof(sa));
	if (strlcpy(sa.sun_path, sockname, sizeof(sa.sun_path)) >= sizeof(sa.sun_path))
		errx(1, "agent path too long");
	sa.sun_family = AF_UNIX;
	umask(0077);
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s == -1)
		err(1, "socket");
	if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) == -1)
		err(1, "bind");
	if (listen(s, 5) == -1)
		err(1, "listen");
	while (1) {
		int fd = accept(s, NULL, NULL);
		if (fd == -1)
			err(1, "accept");
		char cmd[1024];
		int rv = read(fd, cmd, sizeof(cmd) - 1);
		if (rv == -1)
			err(1, "read");
		if (rv == 0) {
			close(fd);
			continue;
		}
		cmd[rv] = '\0';
		if (strncmp(cmd, "QUIT", 4) == 0) {
			close(fd);
			break;
		}
		if (strncmp(cmd, "KEY", 3) == 0) {
			write(fd, keydata, strlen(keydata));
		}
		close(fd);
	}
	reop_freestr(keydata);
	reop_freeseckey(seckey);
	close(s);
	unlink(sockname);
}
#endif

int
main(int argc, char **argv)
{
	const char *pubkeyfile = NULL, *seckeyfile = NULL, *msgfile = NULL,
	    *xfile = NULL;
	char xfilebuf[1024];
	const char *ident = NULL;
	int ch;
	int embedded = 0;
	int quiet = 0;
	int v1compat = 0;
	const char *password = NULL;
	const char *sockname = NULL;
	opt_binary binary = { 0 };
	enum {
		NONE,
		AGENT,
		DECRYPT,
		ENCRYPT,
		GENERATE,
		SIGN,
		VERIFY,
	} verb = NONE;

	while ((ch = getopt(argc, argv, "1CDEGSVZbei:m:np:qs:x:z:")) != -1) {
		switch (ch) {
		case '1':
			v1compat = 1;
			break;
		case 'D':
			if (verb)
				usage(NULL);
			verb = DECRYPT;
			break;
		case 'E':
			if (verb)
				usage(NULL);
			verb = ENCRYPT;
			break;
		case 'G':
			if (verb)
				usage(NULL);
			verb = GENERATE;
			break;
		case 'S':
			if (verb)
				usage(NULL);
			verb = SIGN;
			break;
		case 'V':
			if (verb)
				usage(NULL);
			verb = VERIFY;
			break;
		case 'Z':
			if (verb)
				usage(NULL);
			verb = AGENT;
			break;
		case 'b':
			binary.v = 1;
			break;
		case 'e':
			embedded = 1;
			break;
		case 'i':
			ident = optarg;
			break;
		case 'm':
			msgfile = optarg;
			break;
		case 'n':
			password = "";
			break;
		case 'p':
			pubkeyfile = optarg;
			break;
		case 'q':
			quiet = 1;
			break;
		case 's':
			seckeyfile = optarg;
			break;
		case 'x':
			xfile = optarg;
			break;
		case 'z':
			sockname = optarg;
			break;
		default:
			usage(NULL);
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage(NULL);

	reop_init();

	switch (verb) {
	case AGENT:
		if (!sockname)
			usage("You must specify an agent socket");
		break;
	case ENCRYPT:
	case DECRYPT:
		if (!msgfile)
			usage("You must specify a message-file");
		if (!xfile) {
			if (strcmp(msgfile, "-") == 0)
				usage("must specify encfile with - message");
			if (snprintf(xfilebuf, sizeof(xfilebuf), "%s.enc",
			    msgfile) >= sizeof(xfilebuf))
				errx(1, "path too long");
			xfile = xfilebuf;
		}
		break;
	case SIGN:
	case VERIFY:
		if (!xfile && msgfile) {
			if (strcmp(msgfile, "-") == 0)
				usage("must specify sigfile with - message");
			if (snprintf(xfilebuf, sizeof(xfilebuf), "%s.sig",
			    msgfile) >= sizeof(xfilebuf))
				errx(1, "path too long");
			xfile = xfilebuf;
		}
		break;
	default:
		break;
	}

	switch (verb) {
#if 0
	case AGENT:
		agentserver(sockname, seckeyfile);
		break;
#endif
	case DECRYPT:
		decrypt(pubkeyfile, seckeyfile, msgfile, xfile);
		break;
	case ENCRYPT:
		if (seckeyfile && (!pubkeyfile && !ident))
			usage("specify a pubkey or ident");
		if (pubkeyfile || ident) {
			if (v1compat)
				v1pubencrypt(pubkeyfile, ident, seckeyfile, msgfile, xfile, binary);
			else
				pubencrypt(pubkeyfile, ident, seckeyfile, msgfile, xfile, binary);
		} else
			symencrypt(msgfile, xfile, binary);
		break;
	case GENERATE:
		if (!ident && !(ident= getenv("USER")))
			ident = "unknown";

		/* can specify none, but not only one */
		if ((!pubkeyfile && seckeyfile) ||
		    (!seckeyfile && pubkeyfile))
			usage("must specify pubkey and seckey");
		/* if none, create ~/.reop */
		if (!pubkeyfile && !seckeyfile) {
			char buf[1024];
			const char *home;

			if (!(home = getenv("HOME")))
				errx(1, "can't find HOME");
			snprintf(buf, sizeof(buf), "%s/.reop", home);
			if (mkdir(buf, 0700) == -1 && errno != EEXIST)
				err(1, "Unable to create ~/.reop");
		}
		generate(pubkeyfile, seckeyfile, ident, password);
		break;
	case SIGN:
		if (!msgfile)
			usage("must specify message");
		signfile(seckeyfile, msgfile, xfile, embedded);
		break;
	case VERIFY:
		if (!msgfile && !xfile)
			usage("must specify message or sigfile");
		if (msgfile)
			verifysimple(pubkeyfile, msgfile, xfile, quiet);
		else
			verifyembedded(pubkeyfile, xfile, quiet);
		break;
	default:
		usage(NULL);
		break;
	}

	return 0;
}
#endif
