/*
**   SMTP VRFY Account Enumeration Medusa Module
**
**   ------------------------------------------------------------------------
**    Copyright (C) 2009 Joe Mondloch
**    JoMo-Kun / jmk@foofus.net
**
**    This program is free software; you can redistribute it and/or modify
**    it under the terms of the GNU General Public License version 2,
**    as published by the Free Software Foundation
**
**    This program is distributed in the hope that it will be useful,
**    but WITHOUT ANY WARRANTY; without even the implied warranty of
**    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**    GNU General Public License for more details.
**
**    http://www.gnu.org/licenses/gpl.txt
**
**    This program is released under the GPL with the additional exemption
**    that compiling, linking, and/or using OpenSSL is allowed.
**
**   ------------------------------------------------------------------------
**
**
*/

#include <sys/types.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "module.h"

#define MODULE_NAME    "smtp-vrfy.mod"
#define MODULE_AUTHOR  "JoMo-Kun <jmk@foofus.net>"
#define MODULE_SUMMARY_USAGE  "Brute force module for enumerating accounts via SMTP VRFY"
#define MODULE_VERSION    "2.0"
#define MODULE_VERSION_SVN "$Id: smtp-vrfy.c 1581 2011-07-07 21:34:27Z jmk $"
#define MODULE_SUMMARY_FORMAT  "%s : version %s"
#define MODULE_SUMMARY_FORMAT_WARN  "%s : version %s (%s)"

#define PORT_SMTP 25
#define BUF_SIZE 300
#define RECEIVE_DELAY_1 20 * 1000000
#define RECEIVE_DELAY_2 0.5 * 1000000

typedef struct __MODULE_DATA {
  char *szHELO;
} _MODULE_DATA;


// Tells us whether we are to continue processing or not
enum MODULE_STATE
{
  MSTATE_NEW,
  MSTATE_RUNNING,
  MSTATE_EXITING,
  MSTATE_COMPLETE
};

// Forward declarations
int sayHELO(int hSocket, _MODULE_DATA* _psSessionData);
int sayQUIT(int hSocket);
int tryLogin(int hSocket, sLogin** login, _MODULE_DATA* _psSessionData, char* szLogin, char* szPassword);
int initModule(sLogin* login, _MODULE_DATA *_psSessionData);

// Tell medusa how many parameters this module allows
int getParamNumber()
{
  return 0;    // we don't need no stinking parameters
}

// Displays information about the module and how it must be used
void summaryUsage(char **ppszSummary)
{
  // Memory for ppszSummary will be allocated here - caller is responsible for freeing it
  int  iLength = 0;

  if (*ppszSummary == NULL)
  {
    iLength = strlen(MODULE_SUMMARY_USAGE) + strlen(MODULE_VERSION) + strlen(MODULE_SUMMARY_FORMAT) + 1;
    *ppszSummary = (char*)malloc(iLength);
    memset(*ppszSummary, 0, iLength);
    snprintf(*ppszSummary, iLength, MODULE_SUMMARY_FORMAT, MODULE_SUMMARY_USAGE, MODULE_VERSION);
  } 
  else 
  {
    writeError(ERR_ERROR, "%s reports an error in summaryUsage() : ppszSummary must be NULL when called", MODULE_NAME);
  }
}

/* Display module usage information */
void showUsage()
{
  writeVerbose(VB_NONE, "%s (%s) %s :: %s\n", MODULE_NAME, MODULE_VERSION, MODULE_AUTHOR, MODULE_SUMMARY_USAGE);
  writeVerbose(VB_NONE, "Available module options:");
  writeVerbose(VB_NONE, "  HELO:? (optional)");
  writeVerbose(VB_NONE, "    Sets the name sent via the HELO command.");
  writeVerbose(VB_NONE, "");
  writeVerbose(VB_NONE, "  Usage example: \"-M smtp-vrfy -m HELO:g3rg3 -U accounts.txt -p domain.com\"");
  writeVerbose(VB_NONE, "");
}

// The "main" of the medusa module world - this is what gets called to actually do the work
int go(sLogin* logins, int argc, char *argv[])
{
  int i;
  char *strtok_ptr, *pOpt, *pOptTmp;
  _MODULE_DATA *psSessionData;
  
  psSessionData = malloc(sizeof(_MODULE_DATA));
  memset(psSessionData, 0, sizeof(_MODULE_DATA));

  if ( !(0 <= argc <= 3) )
  {
    // Show usage information
    writeError(ERR_ERROR, "%s is expecting 0 parameters, but it was passed %d", MODULE_NAME, argc);
  } 
  else 
  {
    writeError(ERR_DEBUG_MODULE, "OMG teh %s module has been called!!", MODULE_NAME);

    for (i=0; i<argc; i++) {
      pOptTmp = malloc( strlen(argv[i]) + 1);
      memset(pOptTmp, 0, strlen(argv[i]) + 1);
      strncpy(pOptTmp, argv[i], strlen(argv[i]));
      writeError(ERR_DEBUG_MODULE, "Processing complete option: %s", pOptTmp);
      pOpt = strtok_r(pOptTmp, ":", &strtok_ptr);
      writeError(ERR_DEBUG_MODULE, "Processing option: %s", pOpt);

      if (strcmp(pOpt, "HELO") == 0)
      {
        pOpt = strtok_r(NULL, "\0", &strtok_ptr);
        writeError(ERR_DEBUG_MODULE, "Processing option parameter: %s", pOpt);

        if ( pOpt )
        {
          psSessionData->szHELO = malloc(strlen(pOpt) + 1);
          memset(psSessionData->szHELO, 0, strlen(pOpt) + 1);
          strncpy((char *)psSessionData->szHELO, pOpt, strlen(pOpt));
        }
        else
          writeError(ERR_WARNING, "Method HELO requires value to be set.");
      }
      else
         writeError(ERR_WARNING, "Invalid method: %s.", pOpt);

      free(pOptTmp);
    }

    initModule(logins, psSessionData);
  }  

  FREE(psSessionData);
  return SUCCESS;
}

int initModule(sLogin* psLogin, _MODULE_DATA *_psSessionData)
{
  int hSocket = -1;
  enum MODULE_STATE nState = MSTATE_NEW;
  char* bufReceive;
  int nReceiveBufferSize = 0;
  int nStatus = FAILURE;
  int nBannerStatus = 0;
  sCredentialSet *psCredSet = NULL;
  sConnectParams params;

  psCredSet = malloc( sizeof(sCredentialSet) );
  memset(psCredSet, 0, sizeof(sCredentialSet));

  if (getNextCredSet(psLogin, psCredSet) == FAILURE)
  {
    writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }
  else if (psCredSet->psUser)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s user: %s", MODULE_NAME, psLogin->psServer->pHostIP, psCredSet->psUser->pUser);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] module started for host: %s - no more available users to test.", MODULE_NAME);
    nState = MSTATE_COMPLETE;
  }

  memset(&params, 0, sizeof(sConnectParams));
  params.nPort = PORT_SMTP;
  initConnectionParams(psLogin, &params);

  if (_psSessionData->szHELO == NULL)
  {
    _psSessionData->szHELO = malloc(7);
    memset(_psSessionData->szHELO, 0, 7);
    sprintf(_psSessionData->szHELO, "MEDUSA");
  }

  writeError(ERR_DEBUG_MODULE, "[%s] Set HELO value: %s", MODULE_NAME, _psSessionData->szHELO);

  while (nState != MSTATE_COMPLETE)
  {  
    switch(nState)
    {
      case MSTATE_NEW:
        if (hSocket > 0)
          medusaDisconnect(hSocket);

        if (psLogin->psServer->psHost->iUseSSL > 0)
          hSocket = medusaConnectSSL(&params);
        else
          hSocket = medusaConnect(&params);

        if (hSocket < 0) 
        {
          writeError(ERR_NOTICE, "%s: failed to connect, port %d was not open on %s", MODULE_NAME, params.nPort, psLogin->psServer->pHostIP);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          return FAILURE;
        }

        /* establish initial connection */
        bufReceive = NULL;
        nReceiveBufferSize = 0;
        nStatus = FAILURE;
        nBannerStatus = 0;
        while (bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize))
        {
          if (strstr(bufReceive, "220 ") != NULL)
            nBannerStatus = 1;

          if (nBannerStatus > 0 && (strstr(bufReceive, "\r\n") != NULL))
            nBannerStatus = 2;

          if (nBannerStatus > 1)
          {
            writeError(ERR_DEBUG_MODULE, "[%s] Server sent '220' code.", MODULE_NAME);
            nStatus = SUCCESS;
            FREE(bufReceive);
            break;
          }

          FREE(bufReceive);
        }

        if (nStatus == FAILURE)
        {
          writeError(ERR_DEBUG_MODULE, "[%s] Server did not respond with '220' code. Exiting...", MODULE_NAME);
          psLogin->iResult = LOGIN_RESULT_UNKNOWN;
          nState = MSTATE_EXITING;
          return FAILURE;
          break;
        }
        else
        {
          writeError(ERR_DEBUG_MODULE, "Connected");
          nState = MSTATE_RUNNING;
        }
 
        /* send HELO */
        writeError(ERR_DEBUG_MODULE, "[%s] Sending HELO command.", MODULE_NAME);
        if (sayHELO(hSocket, _psSessionData) == SUCCESS)
          nState = MSTATE_RUNNING;
        else  
          nState = MSTATE_EXITING;

        break;
      case MSTATE_RUNNING:
        nState = tryLogin(hSocket, &psLogin, _psSessionData, psCredSet->psUser->pUser, psCredSet->pPass);

        if (psLogin->iResult != LOGIN_RESULT_UNKNOWN)
        {
          if (getNextCredSet(psLogin, psCredSet) == FAILURE)
          {
            writeError(ERR_ERROR, "[%s] Error retrieving next credential set to test.", MODULE_NAME);
            nState = MSTATE_EXITING;
          }
          else
          {
            if (psCredSet->iStatus == CREDENTIAL_DONE)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] No more available credential sets to test.", MODULE_NAME);
              nState = MSTATE_EXITING;
            }
            else if (psCredSet->iStatus == CREDENTIAL_NEW_USER)
            {
              writeError(ERR_DEBUG_MODULE, "[%s] Starting testing for new user: %s.", MODULE_NAME, psCredSet->psUser->pUser);
              nState = MSTATE_NEW;
            }
            else
              writeError(ERR_DEBUG_MODULE, "[%s] Next credential set - user: %s password: %s", MODULE_NAME, psCredSet->psUser->pUser, psCredSet->pPass);
          }
        }
        break;
      case MSTATE_EXITING:
        sayQUIT(hSocket);
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
        nState = MSTATE_COMPLETE;
        break;
      default:
        writeError(ERR_CRITICAL, "Unknown %s module state %d", MODULE_NAME, nState);
        if (hSocket > 0)
          medusaDisconnect(hSocket);
        hSocket = -1;
        psLogin->iResult = LOGIN_RESULT_UNKNOWN;
        return FAILURE;
    }  
  }

  FREE(psCredSet);
  return SUCCESS;
}

/* Module Specific Functions */

/*
  HELO foo
  250-spamfirewall.domain.com
  250-PIPELINING
  250-SIZE 100000000
  250-VRFY
  250-ETRN
  250 8BITMIME
*/
int sayHELO(int hSocket, _MODULE_DATA* _psSessionData)
{
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;
  int nStatus;
  int nBannerStatus = 0;

  /* send helo string */
  memset(bufSend, 0, sizeof(bufSend));
  sprintf(bufSend, "HELO %.250s\r\n", _psSessionData->szHELO);

  if (medusaSend(hSocket, bufSend, strlen(bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  bufReceive = NULL;
  nReceiveBufferSize = 0;
  nStatus = FAILURE;
  nBannerStatus = 0;
  while (bufReceive = medusaReceiveRaw(hSocket, &nReceiveBufferSize))
  {
    /*  From: http://www.faqs.org/rfcs/rfc959.html
        [SMTP VRFY appears to act in same manner as FTP]
      
        Thus the format for multi-line replies is that the first line
        will begin with the exact required reply code, followed
        immediately by a Hyphen, "-" (also known as Minus), followed by
        text.  The last line will begin with the same code, followed
        immediately by Space <SP>, optionally some text, and the Telnet
        end-of-line code.
    */

    if (strstr(bufReceive, "250 ") != NULL)
      nBannerStatus = 1;

    if (nBannerStatus > 0 && (strstr(bufReceive, "\r\n") != NULL))
      nBannerStatus = 2;

    if (nBannerStatus > 1)
    {
      writeError(ERR_DEBUG_MODULE, "[%s] Server sent '250' code.", MODULE_NAME);
      nStatus = SUCCESS;
      FREE(bufReceive);
      break;
    }

    FREE(bufReceive);
  }

  FREE(bufReceive);
  return nStatus;
}

int sayQUIT(int hSocket)
{
  unsigned char bufSend[BUF_SIZE];

  memset(bufSend, 0, sizeof(bufSend));
  sprintf(bufSend, "QUIT\r\n");

  if (medusaSend(hSocket, bufSend, strlen(bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  return SUCCESS;
}

/*
  VRFY administrator@domain.com
  252 administrator@domain.com
  
  VRFY foo@domain.com
  550 <foo@domain.com>: Recipient address rejected: No such user (foo@domain.com)
  
  VRFY foo@bar.com
  554 <foo@bar.com>: Relay access denied
  
  421 Error: too many errors
*/
int tryLogin(int hSocket, sLogin** psLogin, _MODULE_DATA* _psSessionData, char* szAccount, char* szDomain)
{
  int iRet;
  unsigned char bufSend[BUF_SIZE];
  unsigned char* bufReceive;
  int nReceiveBufferSize = 0;

  /* send helo string */
  memset(bufSend, 0, sizeof(bufSend));
  
  if (strlen(szDomain) > 0)
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Sending: VRFY %.250s@%.250s\r\n", MODULE_NAME, szAccount, szDomain);
    sprintf(bufSend, "VRFY %.250s@%.250s\r\n", szAccount, szDomain);
  }
  else
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Sending: VRFY %.250s\r\n", MODULE_NAME, szAccount);
    sprintf(bufSend, "VRFY %.250s\r\n", szAccount);
  }

  if (medusaSend(hSocket, bufSend, strlen(bufSend), 0) < 0)
  {
    writeError(ERR_ERROR, "%s failed: medusaSend was not successful", MODULE_NAME);
  }

  nReceiveBufferSize = 0;
  bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
  if (bufReceive == NULL)
  {
    writeError(ERR_ERROR, "%s failed: medusaReceive returned no data.", MODULE_NAME);
    return FAILURE;
  }
  else if (strncmp(bufReceive, "250 ", 4) == 0) /* valid account */
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Found valid account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_RUNNING;
  }
  else if (strncmp(bufReceive, "252 ", 4) == 0) /* valid account */
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Found valid account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_SUCCESS;
    iRet = MSTATE_RUNNING;
  }
  else if (strncmp(bufReceive, "550 ", 4) == 0) /* non-existant account */
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Non-existant account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_RUNNING;
  }
  else if (strncmp(bufReceive, "557 ", 4) == 0) /* 557 5.5.2 String does not match anything. */
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Non-existant account: %s", MODULE_NAME, szAccount);
    (*psLogin)->iResult = LOGIN_RESULT_FAIL;
    iRet = MSTATE_RUNNING;
  }
  else if (strncmp(bufReceive, "554 ", 4) == 0) /* invalid domain name */
  {
    writeError(ERR_ERROR, "[%s] Invalid domain name: %s", MODULE_NAME, szDomain);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }
  else
  {
    writeError(ERR_ERROR, "[%s] Unknown response code: %s", MODULE_NAME, bufReceive);
    (*psLogin)->iResult = LOGIN_RESULT_ERROR;
    iRet = MSTATE_EXITING;
  }
  
  /* check if more data is waiting */
  if (medusaDataReadyTimed(hSocket, 0, 20000) > 0)
    bufReceive = medusaReceiveLineDelay(hSocket, &nReceiveBufferSize, RECEIVE_DELAY_1, RECEIVE_DELAY_2);
 
  if (strstr(bufReceive, "421 Error: too many errors"))
  {
    writeError(ERR_DEBUG_MODULE, "[%s] Too many errors. Restarting connection.", MODULE_NAME);
    iRet = MSTATE_NEW;
  }
  
  setPassResult((*psLogin), szDomain);
  return(iRet);
}
