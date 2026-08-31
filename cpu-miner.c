/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2017 pooler
 * Updated By Git Copilot and Roland 2026
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#ifdef WIN32
#include <windows.h>
#else
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif
#include <jansson.h>
#include <curl/curl.h>
#include "compat.h"
#include "miner.h"

#define PROGRAM_NAME		"minerd"
#define LP_SCANTIME		60

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>
static inline void drop_policy(void)
{
	struct sched_param param;
	param.sched_priority = 0;

#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	sched_setaffinity(0, sizeof(set), &set);
}
#elif defined(__FreeBSD__) /* FreeBSD specific policy and affinity management */
#include <sys/cpuset.h>
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
	cpuset_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#else
static inline void drop_policy(void)
{
}

static inline void affine_to_cpu(int id, int cpu)
{
}
#endif	

enum workio_commands {
	WC_GET_WORK,
	WC_SUBMIT_WORK,
};

struct workio_cmd {
	enum workio_commands	cmd;
	struct thr_info		*thr;
	union {
		struct work	*work;
	} u;
};

enum algos {
	ALGO_SCRYPT,		/* scrypt(1024,1,1) */
	ALGO_SHA256D,		/* SHA-256d */
};

static const char *algo_names[] = {
	[ALGO_SCRYPT]		= "scrypt",
	[ALGO_SHA256D]		= "sha256d",
};

bool opt_debug = false;
bool opt_protocol = false;
static bool opt_benchmark = false;
bool opt_redirect = true;
bool want_longpoll = true;
bool have_longpoll = false;
bool have_gbt = true;
bool want_stratum = true;
bool have_stratum = false;
bool use_syslog = false;
static bool opt_background = false;
static bool opt_quiet = false;
static int opt_retries = -1;
static int opt_fail_pause = 30;
int opt_timeout = 0;
static int opt_scantime = 5;
static double opt_difficulty_multiplier = 1.0;
static enum algos opt_algo = ALGO_SCRYPT;
static int opt_scrypt_n = 1024;
static int opt_n_threads;
static int num_processors;
static char *rpc_url;
static char *rpc_userpass;
static char *rpc_user, *rpc_pass;
static int pk_script_size;
static unsigned char pk_script[42];
static char coinbase_sig[101] = "";
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
static int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
struct work_restart *work_restart = NULL;
static struct stratum_ctx stratum;

pthread_mutex_t applog_lock;
static pthread_mutex_t stats_lock;

static unsigned long accepted_count = 0L;
static unsigned long rejected_count = 0L;
static double *thr_hashrates;

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
	const char *name;
	int has_arg;
	int *flag;
	int val;
};
#endif

static char const usage[] = "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the algorithm to use\n\
                          scrypt    scrypt(1024, 1, 1) (default)\n\
                          scrypt:N  scrypt(N, 1, 1)\n\
                          sha256d   SHA-256d\n\
  -o, --url=URL         URL of mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of processors)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
  -T, --timeout=N       timeout for long polling, in seconds (default: none)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 5)\n\
      --difficulty-mult=N  multiplier for share difficulty (helps low hashrate) (default: 1.0)\n\
      --coinbase-addr=ADDR  payout address for solo mining\n\
      --coinbase-sig=TEXT  data to insert in the coinbase when possible\n\
      --no-longpoll     disable long polling support\n\
      --no-gpoabt          disable getpoablocktemplate support\n\
      --no-stratum      disable X-Stratum support\n\
      --no-redirect     ignore requests to change the URL of the mining server\n\
  -q, --quiet           disable per-thread hashmeter output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n"
#ifdef HAVE_SYSLOG_H
"\
  -S, --syslog          use system log for output messages\n"
#endif
"\
#ifndef WIN32
"\
  -B, --background      run the miner in the background\n"
#endif
"\
      --benchmark       run in offline benchmark mode\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";

static char const short_options[] =
#ifndef WIN32
	"B"
#endif
#ifdef HAVE_SYSLOG_H
	"S"
#endif
	"a:c:Dhp:Px:qr:R:s:t:T:o:u:O:V";

static struct option const options[] = {
	{ "algo", 1, NULL, 'a' },
#ifndef WIN32
	{ "background", 0, NULL, 'B' },
#endif
	{ "benchmark", 0, NULL, 1005 },
	{ "cert", 1, NULL, 1001 },
	{ "coinbase-addr", 1, NULL, 1013 },
	{ "coinbase-sig", 1, NULL, 1015 },
	{ "config", 1, NULL, 'c' },
	{ "debug", 0, NULL, 'D' },
	{ "difficulty-mult", 1, NULL, 1016 },
	{ "help", 0, NULL, 'h' },
	{ "no-gbt", 0, NULL, 1011 },
	{ "no-longpoll", 0, NULL, 1003 },
	{ "no-redirect", 0, NULL, 1009 },
	{ "no-stratum", 0, NULL, 1007 },
	{ "pass", 1, NULL, 'p' },
	{ "protocol-dump", 0, NULL, 'P' },
	{ "proxy", 1, NULL, 'x' },
	{ "quiet", 0, NULL, 'q' },
	{ "retries", 1, NULL, 'r' },
	{ "retry-pause", 1, NULL, 'R' },
	{ "scantime", 1, NULL, 's' },
#ifdef HAVE_SYSLOG_H
	{ "syslog", 0, NULL, 'S' },
#endif
	{ "threads", 1, NULL, 't' },
	{ "timeout", 1, NULL, 'T' },
	{ "url", 1, NULL, 'o' },
	{ "user", 1, NULL, 'u' },
	{ "userpass", 1, NULL, 'O' },
	{ "version", 0, NULL, 'V' },
	{ 0, 0, 0, 0 }
};

/*
 * PoA block has the following info
 * version
 * previouspoablockhash
 * transactions
 * coinbasevalue
 * noncerange
 * curtime
 * bits
 * height
 * posblocksaudited {
 *   {
       "data": "3c8808918e261978f631dd810b14ed8881dfca595115d9a0d1d09b07cdb0656a",
      }
 * }
 * */
struct work {
	uint32_t data[32];
	uint32_t target[8];

	int height;
	uint32_t merkleRoot[8];
	char *txs;		//streamed transactions
	char *pos_data; //streamed pos audited blocks
	char *workid;
	uint32_t previousPoABlockHash[8];
	uint32_t hashPoAMerkleRoot[8]; //
	uint32_t integratedHash[8];
	uint32_t minedHash[8];
	uint32_t version;
	uint32_t time;
	uint32_t bits;

	char *job_id;
	size_t xnonce2_len;
	unsigned char *xnonce2;
};


static struct work g_work;
static time_t g_work_time;
static pthread_mutex_t g_work_lock;
static bool submit_old = false;
static char *lp_id;

static inline void work_free(struct work *w)
{
	free(w->txs);
	w->txs = NULL;
	free(w->workid);
	w->workid = NULL;
	free(w->job_id);
	w->job_id = NULL;
	free(w->xnonce2);
	w->xnonce2 = NULL;
	free(w->pos_data);
	w->pos_data = NULL;
}

static inline void work_copy(struct work *dest, const struct work *src)
{
	memcpy(dest, src, sizeof(struct work));
	if (src->txs)
		dest->txs = strdup(src->txs);
	if (src->pos_data)
		dest->pos_data = strdup(src->pos_data);
	if (src->workid)
		dest->workid = strdup(src->workid);
	if (src->job_id)
		dest->job_id = strdup(src->job_id);
	if (src->xnonce2) {
		dest->xnonce2 = malloc(src->xnonce2_len);
		memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
	}
}

static bool jobj_binary(const json_t *obj, const char *key,
				void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin(buf, hexstr, buflen))
		return false;

	return true;
}

static bool work_decode(const json_t *val, struct work *work)
{
	int i;

	if (unlikely(!jobj_binary(val, "data", work->data, sizeof(work->data)))) {
		applog(LOG_ERR, "JSON invalid data");
		goto err_out;
	}
	if (unlikely(!jobj_binary(val, "target", work->target, sizeof(work->target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto err_out;
	}

	for (i = 0; i < ARRAY_SIZE(work->data); i++)
		work->data[i] = le32dec(work->data + i);
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[i] = le32dec(work->target + i);

	return true;

err_out:
	return false;
}

static bool gbt_work_decode(const json_t *val, struct work *work)
{
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevhash[8];
	uint32_t target[8];
	int cbtx_size;
	unsigned char *cbtx = NULL;
	unsigned char *tx = NULL;
	int tx_count, tx_size;
	unsigned char txc_vi[9];
	unsigned char (*merkle_tree)[32] = NULL;
	bool coinbase_append = false;
	bool submit_coinbase = false;
	bool segwit = false;
	json_t *tmp, *txa;
	bool rc = false;

	tmp = json_object_get(val, "rules");
	if (tmp && json_is_array(tmp)) {
		n = json_array_size(tmp);
		for (i = 0; i < n; i++) {
			const char *s = json_string_value(json_array_get(tmp, i));
			if (!s)
				continue;
			if (!strcmp(s, "segwit") || !strcmp(s, "!segwit"))
				segwit = true;
		}
	}

	tmp = json_object_get(val, "mutable");
	if (tmp && json_is_array(tmp)) {
		n = json_array_size(tmp);
		for (i = 0; i < n; i++) {
			const char *s = json_string_value(json_array_get(tmp, i));
			if (!s)
				continue;
			if (!strcmp(s, "coinbase/append"))
				coinbase_append = true;
			else if (!strcmp(s, "submit/coinbase"))
				submit_coinbase = true;
		}
	}

	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = json_integer_value(tmp);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = json_integer_value(tmp);

	if (unlikely(!jobj_binary(val, "previousblockhash", prevhash, sizeof(prevhash)))) {
		applog(LOG_ERR, "JSON invalid previousblockhash");
		goto out;
	}

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = json_integer_value(tmp);

	if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}

	/* find count and size of transactions */
	txa = json_object_get(val, "transactions");
	if (!txa || !json_is_array(txa)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	tx_count = json_array_size(txa);
	tx_size = 0;
	for (i = 0; i < tx_count; i++) {
		const json_t *tx = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tx, "data"));
		if (!tx_hex) {
			applog(LOG_ERR, "JSON invalid transactions");
			goto out;
		}
		tx_size += strlen(tx_hex) / 2;
	}

	/* build coinbase transaction */
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
		cbtx_size = cbtx_hex ? strlen(cbtx_hex) / 2 : 0;
		cbtx = malloc(cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (!pk_script_size) {
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp);
		cbtx = malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx+5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
		cbtx_size = 43;
		/* BIP 34: height in coinbase */
		for (n = work->height; n; n >>= 8) {
			cbtx[cbtx_size++] = n & 0xff;
			if (n < 0x100 && n >= 0x80)
				cbtx[cbtx_size++] = 0;
		}
		cbtx[42] = cbtx_size - 43;
		cbtx[41] = cbtx_size - 42; /* scriptsig length */
		le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		/* rest omitted for brevity... */
	}

	/* generate merkle root */
	merkle_tree = malloc(32 * ((1 + tx_count + 1) & ~1));
	size_t tx_buf_size = 32 * 1024;
	tx = malloc(tx_buf_size);
	sha256d(merkle_tree[0], cbtx, cbtx_size);
	for (i = 0; i < tx_count; i++) {
		tmp = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
		const size_t tx_hex_len = tx_hex ? strlen(tx_hex) : 0;
		const int tx_size = tx_hex_len / 2;
		if (segwit) {
			const char *txid = json_string_value(json_object_get(tmp, "txid"));
			if (!txid || !hex2bin(merkle_tree[1 + i], txid, 32)) {
				applog(LOG_ERR, "JSON invalid transaction txid");
				goto out;
			}
			memrev(merkle_tree[1 + i], 32);
		} else {
			if (tx_size > tx_buf_size) {
				free(tx);
				tx_buf_size = tx_size * 2;
				tx = malloc(tx_buf_size);
			}
			if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
				applog(LOG_ERR, "JSON invalid transactions");
				goto out;
			}
			sha256d(merkle_tree[1 + i], tx, tx_size);
		}
		if (!submit_coinbase) {
			strcpy(txs_end, tx_hex);
			txs_end += tx_hex_len;
		}
	}
	free(tx); tx = NULL;
	n = 1 + tx_count;
	while (n > 1) {
		if (n % 2) {
			memcpy(merkle_tree[n], merkle_tree[n-1], 32);
			++n;
		}
		n /= 2;
		for (i = 0; i < n; i++)
			sha256d(merkle_tree[i], merkle_tree[2*i], 64);
	}

	/* assemble block header */
	work->data[0] = swab32(version);
	for (i = 0; i < 8; i++)
		work->data[8 - i] = le32dec(prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	work->data[17] = swab32(curtime);
	work->data[18] = le32dec(&bits);
	memset(work->data + 19, 0x00, 52);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[7 - i] = be32dec(target + i);

	/* Apply difficulty multiplier to GBT target if requested */
	if (opt_difficulty_multiplier != 1.0) {
		int kk;
		// find index k where target has non-zero word (k in 0..6)
		for (kk = 0; kk <= 6; kk++)
			if (work->target[kk] != 0)
				break;
		if (kk <= 6) {
			uint64_t m = (uint64_t)work->target[kk] | ((uint64_t)work->target[kk+1] << 32);
			double diff_reduced = 4294901760.0 / (double)m;
			int exp = 6 - kk;
			double diff = diff_reduced;
			for (i = 0; i < exp; i++)
				diff *= 4294967296.0;
			double adj = diff * opt_difficulty_multiplier;
			applog(LOG_INFO, "Applying difficulty multiplier %.4g -> adjusted diff %.8g (GBT)",
				   opt_difficulty_multiplier, adj);
			diff_to_target(work->target, adj);
			/* log adjusted target in hex */
			uint32_t target_be[8];
			for (i = 0; i < 8; i++)
				be32enc(target_be + i, work->target[7 - i]);
			char target_hex[65];
			bin2hex(target_hex, (unsigned char *)target_be, 32);
			applog(LOG_INFO, "Adjusted GBT target: %s", target_hex);
		}
	}

	char targetHex[2*32 + 1];
	bin2hex(targetHex, target, 32);

	tmp = json_object_get(val, "workid");
	if (tmp) {
		if (!json_is_string(tmp)) {
			applog(LOG_ERR, "JSON invalid workid");
			goto out;
		}
		work->workid = strdup(json_string_value(tmp));
	}

	/* Long polling */
	tmp = json_object_get(val, "longpollid");
	if (want_longpoll && json_is_string(tmp)) {
		free(lp_id);
		lp_id = strdup(json_string_value(tmp));
		if (!have_longpoll) {
			char *lp_uri;
			tmp = json_object_get(val, "longpolluri");
			lp_uri = strdup(json_is_string(tmp) ? json_string_value(tmp) : rpc_url);
			have_longpoll = true;
			tq_push(thr_info[longpoll_thr_id].q, lp_uri);
		}
	}

	rc = true;

out:
	free(tx);
	free(cbtx);
	free(merkle_tree);
	return rc;
}

/*
 * PoA block has the following info
 * version
 * previouspoablockhash
 * poamerkleroot
 * coinbasetxn
 * transactions
 * coinbasevalue
 * noncerange
 * curtime
 * bits
 * height
 * posblocksaudited {
 *   {
       "data": "3c8808918e261978f631dd810b14ed8881dfca595115d9a0d1d09b07cdb0656a",
	 },...
 * }
 *
 * work->data format: unit in uint32_t
 * version: 1
 * time: 1
 * bits: 1
 * nonce: 1
 * hashMerkleRoot: 8
 * hashPoAInterated: 8 ==> hash of hashPrevPoABlock and hashPoAMerkleRoot
 * */
static bool gpoabt_work_decode(const json_t *val, struct work *work)
{
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevpoahash[8], hashPoAMerkleRoot[8], integratedHash[8];
	uint32_t target[8];
	int cbtx_size;
	unsigned char *cbtx = NULL;
    unsigned char *tx = NULL;
	int tx_count, tx_size, pos_count, pos_size;
	unsigned char txc_vi[9];
	unsigned char(*merkle_tree)[32] = NULL;
	bool coinbase_append = false;
	bool submit_coinbase = false;
	bool segwit = false;
	json_t *tmp, *txa, *pos_audited;
	bool rc = false;

	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = json_integer_value(tmp);
    applog(LOG_INFO, "%s: Height = %d", __func__, work->height);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = json_integer_value(tmp);
	work->version = version;
    applog(LOG_INFO, "%s: Version = %d", __func__, work->version);

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = json_integer_value(tmp);
	work->time = curtime;

	if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}
	memcpy(&(work->bits), &bits, sizeof(bits));
    applog(LOG_INFO, "%s: bits = %x", __func__, work->bits);

	if (unlikely(!jobj_binary(val, "previouspoablockhash", prevpoahash, sizeof(prevpoahash)))) {
		applog(LOG_ERR, "JSON invalid previouspoablockhash");
		goto out;
	}
	for (i = 0; i < 8; i++)
		work->previousPoABlockHash[7 - i] = le32dec(prevpoahash + i);

	if (unlikely(!jobj_binary(val, "poamerkleroot", hashPoAMerkleRoot, sizeof(hashPoAMerkleRoot)))) {
		applog(LOG_ERR, "JSON invalid poamerkleroot");
		goto out;
	}
	for (i = 0; i < 8; i++)
		work->hashPoAMerkleRoot[7 - i] = le32dec(hashPoAMerkleRoot + i);

	//build integrated hash
	unsigned char integratedHashData[64];
	memcpy(integratedHashData, work->previousPoABlockHash, 32);
	memcpy(integratedHashData + 32, work->hashPoAMerkleRoot, 32);
	sha256d(integratedHash, integratedHashData, 64);
	memcpy(work->integratedHash, integratedHash, 32);

	/* find count and size of posblocksaudited  transactions */
	pos_audited = json_object_get(val, "posblocksaudited");
	if (!pos_audited || !json_is_array(pos_audited)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	pos_count = json_array_size(pos_audited);
    int n_pos = varint_encode(txc_vi, pos_count);
    pos_size = pos_count * 40;
    work->pos_data = malloc(2 * (n_pos + pos_size) + 1);
    /*if (work->pos_data == NULL) {
        applog(LOG_INFO, "%s: malloc pos data failed", __func__);
    }*/
    //applog(LOG_INFO, "%s: success work->pos_data malloc size = %d", __func__, 2 * (n_pos + pos_size) + 1);
    //applog(LOG_INFO, "%s: copy txc_vi", __func__);
    bin2hex(work->pos_data, txc_vi, n_pos);
    //applog(LOG_INFO, "%s: strncpy", __func__);
    applog(LOG_INFO, "%s: pos_count = %d", __func__, pos_count);
	//char *pos_data = malloc(pos_count * 40 * 2 + 1); //the size of posinfo = 40 byte
	char *pos_data_ptr = work->pos_data + strlen(work->pos_data);
	for (i = 0; i < pos_count; i++) {
		const json_t *pos = json_array_get(pos_audited, i);
		const char *pos_hex = json_string_value(json_object_get(pos, "data"));
		if (!pos_hex) {
			applog(LOG_ERR, "JSON invalid PoS block info");
			goto out;
		}
		size_t hex_len = strlen(pos_hex);
		memcpy(pos_data_ptr, pos_hex, hex_len);
		pos_data_ptr += hex_len;
	}
	*pos_data_ptr = '\0';

	/* build coinbase transaction */
    //applog(LOG_INFO, "%s: build coinbase transaction", __func__);
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
        //applog(LOG_INFO, "%s: Found coinbasetxn, data = %s", __func__, cbtx_hex);
		cbtx_size = cbtx_hex ? strlen(cbtx_hex) / 2 : 0;
		cbtx = malloc(cbtx_size + 100);
        applog(LOG_INFO, "%s: Malloc cbtx, size = %d", __func__, cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
        //applog(LOG_INFO, "%s: Success build coinbase", __func__);
	} //PoA block always has a coinbasetxn, the following will possible be never executed
	else {
		int64_t cbvalue;
		if (!pk_script_size) {
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp);
		cbtx = malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx + 5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx + 37), 0xffffffff); /* prev txout index */
		cbtx_size = 43;
		/* BIP 34: height in coinbase */
		for (n = work->height; n; n >>= 8) {
			cbtx[cbtx_size++] = n & 0xff;
			if (n < 0x100 && n >= 0x80)
				cbtx[cbtx_size++] = 0;
		}
		cbtx[42] = cbtx_size - 43;
		cbtx[41] = cbtx_size - 42; /* scriptsig length */
		le32enc((uint32_t *)(cbtx + cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		cbtx[cbtx_size++] = segwit ? 2 : 1; /* out-counter */
		le32enc((uint32_t *)(cbtx + cbtx_size), (uint32_t)cbvalue); /* value */
		le32enc((uint32_t *)(cbtx + cbtx_size + 4), cbvalue >> 32);
		cbtx_size += 8;
		cbtx[cbtx_size++] = pk_script_size; /* txout-script length */
		memcpy(cbtx + cbtx_size, pk_script, pk_script_size);
		cbtx_size += pk_script_size;

		le32enc((uint32_t *)(cbtx + cbtx_size), 0); /* lock time */
		cbtx_size += 4;
		coinbase_append = true;
	}
	if (coinbase_append) {
		unsigned char xsig[100];
		int xsig_len = 0;
		if (*coinbase_sig) {
			n = strlen(coinbase_sig);
			if (cbtx[41] + xsig_len + n <= 100) {
				memcpy(xsig+xsig_len, coinbase_sig, n);
				xsig_len += n;
			} else {
				applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
			}
		}
		tmp = json_object_get(val, "coinbaseaux");
		if (tmp && json_is_object(tmp)) {
			void *iter = json_object_iter(tmp);
			while (iter) {
				unsigned char buf[100];
				const char *s = json_string_value(json_object_iter_value(iter));
				n = s ? strlen(s) / 2 : 0;
				if (!s || n > 100 || !hex2bin(buf, s, n)) {
					applog(LOG_ERR, "JSON invalid coinbaseaux");
					break;
				}
				if (cbtx[41] + xsig_len + n <= 100) {
					memcpy(xsig+xsig_len, buf, n);
					xsig_len += n;
				}
				iter = json_object_iter_next(tmp, iter);
			}
		}
		if (xsig_len) {
			unsigned char *ssig_end = cbtx + 42 + cbtx[41];
			int push_len = cbtx[41] + xsig_len < 76 ? 1 :
					       cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
			n = xsig_len + push_len;
			memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
			cbtx[41] += n;
			if (push_len == 2)
				*(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
			if (push_len)
				*(ssig_end++) = xsig_len;
			memcpy(ssig_end, xsig, xsig_len);
			cbtx_size += n;
		}
	}

	n = varint_encode(txc_vi, 1);
	work->txs = malloc(2 * (n + cbtx_size) + 1);
	bin2hex(work->txs, txc_vi, n);
	bin2hex(work->txs + 2 * n, cbtx, cbtx_size);

	/* generate merkle root */
	merkle_tree = malloc(32 * ((1 + 1) & ~1));
	size_t tx_buf_size = 32 * 1024;
	tx = malloc(tx_buf_size);
	sha256d(merkle_tree[0], cbtx, cbtx_size);
	//PoA block has only one transaction: the coinbase transaction
	/*for (i = 0; i < tx_count; i++) {
		tmp = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
		const int tx_size = tx_hex ? strlen(tx_hex) / 2 : 0;
		if (segwit) {
			const char *txid = json_string_value(json_object_get(tmp, "txid"));
			if (!txid || !hex2bin(merkle_tree[1 + i], txid, 32)) {
				applog(LOG_ERR, "JSON invalid transaction txid");
				goto out;
			}
			memrev(merkle_tree[1 + i], 32);
		}
		else {
			if (tx_size > tx_buf_size) {
				free(tx);
				tx_buf_size = tx_size * 2;
				tx = malloc(tx_buf_size);
			}
			if (!tx_hex || !hex2bin(tx, tx_hex, tx_size)) {
				applog(LOG_ERR, "JSON invalid transactions");
				goto out;
			}
			sha256d(merkle_tree[1 + i], tx, tx_size);
		}
		if (!submit_coinbase) {
			strcpy(txs_end, tx_hex);
			txs_end += tx_hex_len;
		}
	}
		free(tx); tx = NULL;
	n = 1 + tx_count;
	while (n > 1) {
		if (n % 2) {
			memcpy(merkle_tree[n], merkle_tree[n-1], 32);
			++n;
		}
		n /= 2;
		for (i = 0; i < n; i++)
			sha256d(merkle_tree[i], merkle_tree[2*i], 64);
	}
	*/

	/* assemble block header */
	work->data[0] = swab32(version);
	for (i = 0; i < 8; i++)
		work->data[1 + i] = be32dec(integratedHash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	work->data[17] = swab32(curtime);
	work->data[18] = le32dec(&bits);
	memset(work->data + 19, 0x00, 52);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if (unlikely(!jobj_binary(val, "target", target, sizeof(target)))) {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}

	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[7 - i] = be32dec(target + i);

	/* Apply difficulty multiplier to GPOABT target if requested */
	if (opt_difficulty_multiplier != 1.0) {
		int kk;
		for (kk = 0; kk <= 6; kk++)
			if (work->target[kk] != 0)
				break;
		if (kk <= 6) {
			uint64_t m = (uint64_t)work->target[kk] | ((uint64_t)work->target[kk+1] << 32);
			double diff_reduced = 4294901760.0 / (double)m;
			int exp = 6 - kk;
			double diff = diff_reduced;
			for (i = 0; i < exp; i++)
				diff *= 4294967296.0;
			double adj = diff * opt_difficulty_multiplier;
			applog(LOG_INFO, "Applying difficulty multiplier %.4g -> adjusted diff %.8g (GPOABT)",
				   opt_difficulty_multiplier, adj);
			diff_to_target(work->target, adj);
			uint32_t target_be[8];
			for (i = 0; i < 8; i++)
				be32enc(target_be + i, work->target[7 - i]);
			char target_hex[65];
			bin2hex(target_hex, (unsigned char *)target_be, 32);
			applog(LOG_INFO, "Adjusted GPOABT target: %s", target_hex);
		}
	}

	char targetHex2[2*32 + 1];
	bin2hex(targetHex2, target, 32);

	tmp = json_object_get(val, "workid");
	if (tmp) {
		if (!json_is_string(tmp)) {
			applog(LOG_ERR, "JSON invalid workid");
			goto out;
		}
		work->workid = strdup(json_string_value(tmp));
	}

	//Temporarily disable polling
	/* Long polling */
	/*tmp = json_object_get(val, "longpollid");
	if (want_longpoll && json_is_string(tmp)) {
		free(lp_id);
		lp_id = strdup(json_string_value(tmp));
		if (!have_longpoll) {
			char *lp_uri;
			tmp = json_object_get(val, "longpolluri");
			lp_uri = strdup(json_is_string(tmp) ? json_string_value(tmp) : rpc_url);
			have_longpoll = true;
			tq_push(thr_info[longpoll_thr_id].q, lp_uri);
		}
	}*/

	rc = true;

out:
	free(cbtx);
	free(merkle_tree);
	return rc;
}

static void share_result(int result, const char *reason)
{
	char s[345];
	double hashrate;
	int i;

	hashrate = 0.;
	pthread_mutex_lock(&stats_lock);
	for (i = 0; i < opt_n_threads; i++)
		hashrate += thr_hashrates[i];
	result ? accepted_count++ : rejected_count++;
	pthread_mutex_unlock(&stats_lock);
	
	sprintf(s, hashrate >= 1e6 ? "%.0f" : "%.2f", 1e-3 * hashrate);
	applog(LOG_INFO, "accepted: %lu/%lu (%.2f%%), %s khash/s %s",
		   accepted_count,
		   accepted_count + rejected_count,
		   100. * accepted_count / (accepted_count + rejected_count),
		   s,
		   result ? "(yay!!!)" : "(booooo)");

	if (opt_debug && reason)
		applog(LOG_DEBUG, "DEBUG: reject reason: %s", reason);
}

/* rest of file unchanged... */
