/*
 * Copyright (C) 2004, 2005 Stig Venaas <venaas@uninett.no>
 * $Id: ldap2zone.c,v 1.1 2007/07/24 15:18:00 atkac Exp $
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#define LDAP_DEPRECATED 1

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <ldap.h>

struct string {
    void *data;
    size_t len;
};

struct assstack_entry {
    struct string key;
    struct string val;
    struct assstack_entry *next;
};

struct assstack_entry *assstack_find(struct assstack_entry *stack, struct string *key);
void assstack_push(struct assstack_entry **stack, struct assstack_entry *item);
void assstack_insertbottom(struct assstack_entry **stack, struct assstack_entry *item);
void printsoa(struct string *soa);
void printrrs(char *defaultttl, struct assstack_entry *item);
void print_zone(char *defaultttl, struct assstack_entry *stack);
void usage(char *name);
void err(char *name, const char *msg);
int putrr(struct assstack_entry **stack, struct berval *name, char *type, char *ttl, struct berval *val);

struct assstack_entry *assstack_find(struct assstack_entry *stack, struct string *key) {
    for (; stack; stack = stack->next)
	if (stack->key.len == key->len && !memcmp(stack->key.data, key->data, key->len))
	    return stack;
    return NULL;
}

void assstack_push(struct assstack_entry **stack, struct assstack_entry *item) {
    item->next = *stack;
    *stack = item;
}

void assstack_insertbottom(struct assstack_entry **stack, struct assstack_entry *item) {
    struct assstack_entry *p;
    
    item->next = NULL;
    if (!*stack) {
	*stack = item;
	return;
    }
    /* find end, should keep track of end somewhere */
    /* really a queue, not a stack */
    p = *stack;
    while (p->next)
	p = p->next;
    p->next = item;
}

void printsoa(struct string *soa) {
    char *s;
    size_t i;
    
    s = (char *)soa->data;
    i = 0;
    while (i < soa->len) {
	putchar(s[i]);
	if (s[i++] == ' ')
	    break;
    }
    while (i < soa->len) {
	putchar(s[i]);
	if (s[i++] == ' ')
	    break;
    } 
    printf("(\n\t\t\t\t");
    while (i < soa->len) {
	putchar(s[i]);
	if (s[i++] == ' ')
	    break;
    }
    printf("; Serialnumber\n\t\t\t\t");
    while (i < soa->len) {
	if (s[i] == ' ')
	    break;
	putchar(s[i++]);
    }
    i++;
    printf("\t; Refresh\n\t\t\t\t");
    while (i < soa->len) {
	if (s[i] == ' ')
	    break;
	putchar(s[i++]);
    }
    i++;
    printf("\t; Retry\n\t\t\t\t");
    while (i < soa->len) {
	if (s[i] == ' ')
	    break;
	putchar(s[i++]);
    }
    i++;
    printf("\t; Expire\n\t\t\t\t");
    while (i < soa->len) {
	putchar(s[i++]);
    }
    printf(" )\t; Minimum TTL\n");
}

void printrrs(char *defaultttl, struct assstack_entry *item) {
    struct assstack_entry *stack;
    char *s;
    int first;
    size_t i;
    char *ttl, *type;
    int top;
    
    s = (char *)item->key.data;

    if (item->key.len == 1 && *s == '@') {
	top = 1;
	printf("@\t");
    } else {
	top = 0;
	for (i = 0; i < item->key.len; i++)
	    putchar(s[i]);
	if (item->key.len < 8)
	    putchar('\t');
	putchar('\t');
    }
    
    first = 1;
    for (stack = (struct assstack_entry *) item->val.data; stack; stack = stack->next) {
	ttl = (char *)stack->key.data;
	s = strchr(ttl, ' ');
	*s++ = '\0';
	type = s;
	
	if (first)
	    first = 0;
        else
	    printf("\t\t");
	    
	if (strcmp(defaultttl, ttl))
	    printf("%s", ttl);
	putchar('\t');
	
	if (top) {
	    top = 0;
	    printf("IN\t%s\t", type);
	    /* Should always be SOA here */
	    if (!strcmp(type, "SOA")) {
		printsoa(&stack->val);
		continue;
	    }
	} else
	    printf("%s\t", type);

	s = (char *)stack->val.data;
	for (i = 0; i < stack->val.len; i++)
	    putchar(s[i]);
	putchar('\n');
    }
}

void print_zone(char *defaultttl, struct assstack_entry *stack) {
    printf("$TTL %s\n", defaultttl);
    for (; stack; stack = stack->next)
	printrrs(defaultttl, stack);
};

void usage(char *name) {
    fprintf(stderr, "Usage:%s zone-name LDAP-URL default-ttl [serial]\n", name);
    exit(1);
};

void err(char *name, const char *msg) {
    fprintf(stderr, "%s: %s\n", name, msg);
    exit(1);
};

int putrr(struct assstack_entry **stack, struct berval *name, char *type, char *ttl, struct berval *val) {
    struct string key;
    struct assstack_entry *rr, *rrdata;
    
    /* Do nothing if name or value have 0 length */
    if (!name->bv_len || !val->bv_len)
	return 0;

    /* see if already have an entry for this name */
    key.len = name->bv_len;
    key.data = name->bv_val;

    rr = assstack_find(*stack, &key);
    if (!rr) {
	/* Not found, create and push new entry */
	rr = (struct assstack_entry *) malloc(sizeof(struct assstack_entry));
	if (!rr)
	    return -1;
	rr->key.len = name->bv_len;
	rr->key.data = (void *) malloc(rr->key.len);
	if (!rr->key.data) {
	    free(rr);
	    return -1;
	}
	memcpy(rr->key.data, name->bv_val, name->bv_len);
	rr->val.len = sizeof(void *);
	rr->val.data = NULL;
	if (name->bv_len == 1 && *(char *)name->bv_val == '@')
	    assstack_push(stack, rr);
	else
	    assstack_insertbottom(stack, rr);
    }

    rrdata = (struct assstack_entry *) malloc(sizeof(struct assstack_entry));
    if (!rrdata) {
	free(rr->key.data);
	free(rr);
	return -1;
    }
    rrdata->key.len = strlen(type) + strlen(ttl) + 1;
    rrdata->key.data = (void *) malloc(rrdata->key.len);
    if (!rrdata->key.data) {
	free(rrdata);
	free(rr->key.data);
	free(rr);
	return -1;
    }
    sprintf((char *)rrdata->key.data, "%s %s", ttl, type);
	
    rrdata->val.len = val->bv_len;
    rrdata->val.data = (void *) malloc(val->bv_len);
    if (!rrdata->val.data) {
	free(rrdata->key.data);
	free(rrdata);
	free(rr->key.data);
	free(rr);
	return -1;
    }
    memcpy(rrdata->val.data, val->bv_val, val->bv_len);

    if (!strcmp(type, "SOA"))
	assstack_push((struct assstack_entry **) &(rr->val.data), rrdata);
    else
	assstack_insertbottom((struct assstack_entry **) &(rr->val.data), rrdata);
    return 0;
}

int main(int argc, char **argv) {
    char *s, *hostporturl, *base = NULL;
    char *ttl, *defaultttl;
    LDAP *ld;
    char *fltr = NULL;
    LDAPMessage *res, *e;
    char *a, **ttlvals, **soavals, *serial;
    struct berval **vals, **names;
    char type[64];
    BerElement *ptr;
    int i, j, rc, msgid;
    struct assstack_entry *zone = NULL;
    
    if (argc < 4 || argc > 5)
        usage(argv[0]);

    hostporturl = argv[2];

    if (hostporturl != strstr( hostporturl, "ldap"))
	err(argv[0], "Not an LDAP URL");

    s = strchr(hostporturl, ':');

    if (!s || strlen(s) < 3 || s[1] != '/' || s[2] != '/')
	err(argv[0], "Not an LDAP URL");

    s = strchr(s+3, '/');
    if (s) {
	*s++ = '\0';
	base = s;
	s = strchr(base, '?');
	if (s)
	    err(argv[0], "LDAP URL can only contain host, port and base");
    }

    defaultttl = argv[3];
    
    rc = ldap_initialize(&ld, hostporturl);
    if (rc != LDAP_SUCCESS)
	err(argv[0], "ldap_initialize() failed");

    if (argc == 5) {
	/* serial number specified, check if different from one in SOA */
	fltr = (char *)malloc(strlen(argv[1]) + strlen("(&(relativeDomainName=@)(zoneName=))") + 1);
	sprintf(fltr, "(&(relativeDomainName=@)(zoneName=%s))", argv[1]);
	msgid = ldap_search(ld, base, LDAP_SCOPE_SUBTREE, fltr, NULL, 0);
	if (msgid == -1)
	    err(argv[0], "ldap_search() failed");

	while ((rc = ldap_result(ld, msgid, 0, NULL, &res)) != LDAP_RES_SEARCH_RESULT ) {
	    /* not supporting continuation references at present */
	    if (rc != LDAP_RES_SEARCH_ENTRY)
		err(argv[0], "ldap_result() returned cont.ref? Exiting");

	    /* only one entry per result message */
	    e = ldap_first_entry(ld, res);
	    if (e == NULL) {
		ldap_msgfree(res);
		err(argv[0], "ldap_first_entry() failed");
	    }
	
	    soavals = ldap_get_values(ld, e, "SOARecord");
	    if (soavals)
		break;
	}

	ldap_msgfree(res);
	if (!soavals) {
		err(argv[0], "No SOA Record found");
	}
	
	/* We have a SOA, compare serial numbers */
	/* Only checkinf first value, should be only one */
	s = strchr(soavals[0], ' ');
	s++;
	s = strchr(s, ' ');
	s++;
	serial = s;
	s = strchr(s, ' ');
	*s = '\0';
	if (!strcmp(serial, argv[4])) {
	    ldap_value_free(soavals);
	    err(argv[0], "serial numbers match");
	}
	ldap_value_free(soavals);
    }

    if (!fltr)
	fltr = (char *)malloc(strlen(argv[1]) + strlen("(zoneName=)") + 1);
    if (!fltr)
	err(argv[0], "Malloc failed");
    sprintf(fltr, "(zoneName=%s)", argv[1]);

    msgid = ldap_search(ld, base, LDAP_SCOPE_SUBTREE, fltr, NULL, 0);
    if (msgid == -1)
	err(argv[0], "ldap_search() failed");

    while ((rc = ldap_result(ld, msgid, 0, NULL, &res)) != LDAP_RES_SEARCH_RESULT ) {
	/* not supporting continuation references at present */
	if (rc != LDAP_RES_SEARCH_ENTRY)
	    err(argv[0], "ldap_result() returned cont.ref? Exiting");

	/* only one entry per result message */
	e = ldap_first_entry(ld, res);
	if (e == NULL) {
	    ldap_msgfree(res);
	    err(argv[0], "ldap_first_entry() failed");
	}
	
	names = ldap_get_values_len(ld, e, "relativeDomainName");
	if (!names)
	    continue;
	
	ttlvals = ldap_get_values(ld, e, "dNSTTL");
	ttl = ttlvals ? ttlvals[0] : defaultttl;

	for (a = ldap_first_attribute(ld, e, &ptr); a != NULL; a = ldap_next_attribute(ld, e, ptr)) {
	    char *s;

	    for (s = a; *s; s++)
		*s = toupper(*s);
	    s = strstr(a, "RECORD");
	    if ((s == NULL) || (s == a) || (s - a >= (signed int)sizeof(type))) {
		ldap_memfree(a);
		continue;
	    }
			
	    strncpy(type, a, s - a);
	    type[s - a] = '\0';
	    vals = ldap_get_values_len(ld, e, a);
	    if (vals) {
		for (i = 0; vals[i]; i++)
		    for (j = 0; names[j]; j++)
			if (putrr(&zone, names[j], type, ttl, vals[i]))
			    err(argv[0], "malloc failed");
		ldap_value_free_len(vals);
	    }
	    ldap_memfree(a);
	}

	if (ptr)
	    ber_free(ptr, 0);
	if (ttlvals)
	    ldap_value_free(ttlvals);
	ldap_value_free_len(names);
	/* free this result */
	ldap_msgfree(res);
    }

    /* free final result */
    ldap_msgfree(res);

    print_zone(defaultttl, zone);
    return 0;
}
