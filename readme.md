# NFC Tag Identifier

This class and sample app tries to identify an NFC tag tapped to the NFC-reader and retrieves some useful 
information about the tag, e.g. exact Tag type and available extra functionalities.

**This is an unfinished project at the moment and only and a handful tags are included, please wait for updates.**

**Note:** as I'm possessing only some of the tags checked with this class you find an extra boolean field "isTested" - 
this is TRUE if I could test the function with a real NFC tag of this type.

For all NFC-tags checked within this class you find the datasheets in the docs-folder of this repository and below 
there are the links to the newest datasheets - please use always the origin source instead of the preloaded 
ones.

## MIFARE type identification procedure

Get the document here: https://www.nxp.com/docs/en/application-note/AN10833.pdf

https://android.googlesource.com/platform/frameworks/base/+/48a5ed5/core/java/android/nfc/tech/TagTechnology.java

## Mifare Classic family

Some tag facts: 7-byte UID or 4-byte NUID identifier, Individual set of two keys per sector to support multi-application with key hierarchy, 
the data is organized in sectors with of 4 blocks each (last / 4th block containts the keys and access rights); each block is 16 bytes long.  

// for details see: https://android.googlesource.com/platform/frameworks/base/+/48a5ed5/core/java/android/nfc/tech/MifareClassic.java
// size could be 320 / SIZE_MINI, 1024 / SIZE_1K, 2048 / SIZE_2K or 4096 / SIZE_4K

Mifare Classic mini: Total memory 320 bytes, Get the datasheet MF1ICS20 here: http://www.orangetags.com/wp-content/downloads/datasheet/NXP/MF1ICS20.pdf

Mifare Classic 1K: Total memory 1024 bytes. Get the datasheet MF1S50yyX here: https://www.datasheetarchive.com/pdf/download.php?id=bee960138d6124d3df95eb5fbf45fb736c3438&type=P&term=MIFARE%2520Classic%2520Command

Mifare Classic 1K + 4K: Total memory 1024 and 4096 bytes. Get the datasheet  here: https://shop.sonmicro.com/Downloads/MIFARECLASSIC-UM.pdf

Mifare Classic EV1 1K: Total memory . Get the datasheet MF1S50YYX_V1 here: https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf

Mifare Classic EV1 4K: Total memory . Get the datasheet MF1S70YYX_V1 here: https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf

https://android.googlesource.com/platform/frameworks/base/+/48a5ed5/core/java/android/nfc/tech/MifareClassic.java

## Mifare Ultralight family

Some tag facts: 7-byte UID in accordance with ISO/IEC 14443-3 for each device, 32-bit user definable One-Time Programmable (OTP) area, 
Field programmable read-only locking function per page, the data is organized in pages of 4 byte of data each.

For Ultralight C additionally: 3DES Authentication, Anti-cloning support by unique 7-byte serial number for each device, 
32-bit user programmable OTP area, Field programmable read-only locking function per page for first 512-bit, 
Read-only locking per block for the memory above 512 bit

For Ultralight EV1 additionally: 32-bit user definable One-Time Programmable (OTP) area, 3 independent 24-bit true one-way counters, 
Field programmable read-only locking function per page (per 2 pages for the extended memory section), ECC based originality signature, 
32-bit password protection to prevent unintended memory operations.

1) Mifare Ultralight: Total memory 64 bytes. Get the datasheet MF0ICU1 here: https://www.nxp.com/docs/en/data-sheet/MF0ICU1.pdf
2) Mifare Ultralight C: Total memory 192 bytes. Get the datasheet here MF0ICU2: https://www.nxp.com/docs/en/data-sheet/MF0ICU2.pdf
3) Mifare Ultralight EV1: Total memory 64 and 144 bytes. Get the datasheet here: https://www.nxp.com/docs/en/data-sheet/MF0ULX1.pdf

## Mifare DESFire family

Some tag facts: Flexible file system, Up to 28 applications simultaneously on one PICC, Up to 16 files in each application, 
Unique 7 Byte serial number for each device, Mutual three pass authentication, Hardware DES/3DES Data encryption on RF-channel 
with replay attack protection using 56/112 bit Keys featuring key versioning, Data Authenticity by 4 Byte MAC, Authentication 
on Application level, Hardware exception sensors, Self-securing file system. The data is organized in files.

For DESFire EV1 additionally: Up to 32 files in each application (standard data file, back-up data file, value file, 
linear record file and cyclic record file), File size is determined during creation, Common Criteria Certification: EAL4+ 
(Hardware and Software), Optional “RANDOM” ID for enhance security and privacy, Mutual three-pass authentication,
1 card master key and up to 14 keys per application, Hardware DES using 56/112/168 bit keys featuring key version, 
data authenticity by 8 byte CMAC, Hardware AES using 128-bit keys featuring key version, data authenticity by 8 byte CMAC, 
Data encryption on RF-channel, 

For DESFire EV2 additionally: MIsmartApp (Delegated Application Management), Memory reuse in DAM applications (Format Application), 
Transaction MAC on application level, Multiple Key Sets per application with fast key rolling mechanism (up to 16 sets), 
Accessing files from any two applications during a single transaction, Multiple keys assignments for each file access right (up to 8), 
Virtual Card Architecture for enhanced card/application selection on multi-VC devices with privacy protection, 
Proximity Check for protection against Relay Attacks, Originality Check for proof of genuine NXP’s product, 
New EV2 Secure Messaging based on AES (similar with MIFARE Plus’s secure messaging)

For DESFire EV3 additionally: Common Criteria certification: EAL5+ (Hardware and Software), Self-securing file system, 
Transaction MAC signed with secret key per application, Secure Unique NFC (SUN) enabled by Secure Dynamic Messaging (SDM) 
which is mirrored as text into the NDEF message (compatible with NTAG DNA), NFC Forum Type 4 Tag certified (Certificate ID. 58652)


There are 3 tags available and the datasheet covers all of them MF3ICDx21_41_81 : https://www.nxp.com/docs/en/data-sheet/MF3ICDX21_41_81_SDS.pdf

Mifare DESFire Light MF2DL(H)x0: https://www.nxp.com/docs/en/data-sheet/MF2DLHX0.pdf

Mifare DESFire EV1 MF3ICDX21_41_81_SDS: https://www.nxp.com/docs/en/data-sheet/MF3ICDX21_41_81_SDS.pdf

Mifare DESFire EV2 MF3DX2_MF3DHX2_SDS: https://www.nxp.com/docs/en/data-sheet/MF3DX2_MF3DHX2_SDS.pdf

Mifare DESFire EV3 MF3D(H)x3: https://www.nxp.com/docs/en/data-sheet/MF3DHx3_SDS.pdf

Mifare DESFire EV3 Quick start guide: https://www.nxp.com/docs/en/application-note/AN12753.pdf

Mifare DESFire EV3 feature and functionality comparison to other MIFARE DESFire products: https://www.nxp.com/docs/en/application-note/AN12752.pdf

MIFARE DESFire as Type 4 Tag AN11004: https://www.nxp.com/docs/en/application-note/AN11004.pdf


TAPLinx project https://github.com/dfpalomar/TapLinxSample/

https://stackoverflow.com/questions/41249713/configure-mifare-desfire-ev1-as-nfc-forum-type-4-tag-for-ndef

https://stackoverflow.com/questions/37675905/create-standard-data-file-in-mifare-desfire

For Originality signature verification see: Mifare DESFire Light Features and Hints AN12343.pdf

pages 86-88:
```plaintext
11 Originality Checking
The originality check allows verification of the genuineness of MIFARE DESFire Light.
Two ways are offered to check the originality of the PICC:
• Symmetric Originality Check - The first option is based on a symmetric authentication.
• Asymmetric Originality Check - The second option works on the verification of an
asymmetric signature that can be retrieved from the card.
11.1 Symmetric Originality Check
Four secret symmetric Originality Keys of key type AES are present on each individual
MIFARE DESFire Light IC on PICC level.
• The keys are written on the IC at the production in the NXP factory.
• Keys are created in NXP factory HSM and never leave the secure environment.
• The keys can`t be changed after the IC leaves the NXP factory.
• Originality Check is done by executing a successful LRP Authentication with one
of the Originality keys. Therefore LRP mode needs to be enabled with command
Cmd.SetConfiguration beforehand.
• If the authentication with one of the Originality Keys is successful, the Originality Check
is successful and the authenticity of the IC is proven.
11.2 Asymmetric Originality Check
MIFARE DESFire Light contains the NXP Originality Signature, to be able to verify
with a certain probability that the IC is really based on silicon manufactured by NXP
Semiconductors.
Each MIFARE DESFire Light IC contains a 56 byte long elliptic curve signature, using the
secp224r1 curve. The input data for signature creation is the 7 byte UID of the IC.
Signature characteristics:
• The signature is computed according to Elliptic Curve DSA (ECDSA) based on the UID
of the IC.
• The asymmetric key pair (private key and public key) is created securely in NXP`s
HSM. The private key remains stored in the high secure HSM inside NXP premises.
The public key can be handed out.
• The resulting signature is 56 bytes long and according to SEC standard the secp224r1
curve is taken for signature creation and validation.
• A chip unique signature is embedded into each IC during manufacturing. The signature
is created using the private key and signing the UID of the IC.
• The signature can be read out from the final IC, and the public key can be used to
verify the signature which was embedded into the chip.
11.2.1 Originality Signature Verification
The steps for verifying the embedded Originality Signature of a MIFARE DESFire Light
IC are the following:
• Activate the IC on ISO/IEC 14443-4
NXP Semiconductors AN12343
MIFARE DESFire Light Features and Hints
AN12343 All information provided in this document is subject to legal disclaimers. © NXP B.V. 2020. All rights reserved.
Application note Rev. 1.1 — 20 January 2020
COMPANY PUBLIC 522511 87 / 93
• Retrieve the UID from the PICC
• Retrieve the Originality Signature (56 bytes) from the PICC by using the Read_Sig
command
• Verify the retrieved signature by applying an ECDSA signature verification using the
corresponding public key
Originality Check public key value for MIFARE DESFire Light:
0x040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBB
F7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D
Byte 1 of the public key, here using the value 0x04, signalizes the IETF protocol SEC1
representation of a point on an elliptic curve, which is a sequence of the fields as seen in
Table 43.
The following 28 bytes represent the x coordinate of the public key.
And the last 28 bytes represent the y coordinate of the public key.
Table 43. SEC1 point representation
Field Description
B0 {02, 03, 04}, where 02 or 03 represent a
compressed point (x only), while 04 represents
a complete point (x, y)
X x coordinate of a point
Y y coordinate of a point, optional (only present
for B0 = 0x04)
The command steps and parameter details for the signature verification flow can be seen
in Table 44.
Table 44. Asymmetric Originality Signature Verification
Step Command Data Message
1 Cmd Code = 3C
2 Cmd Header = 00
3 C-APDU
Read_Sig
> 903C0000010000
4 R-APDU
(56 bytes ECDSA signature ||
response code)
< 1CA298FC3F0F04A329254AC0DF7A3EB8E756C
076CD1BAAF47B8BBA6DCD78BCC64DFD3E80
E679D9A663CAE9E4D4C2C77023077CC549CE
4A619190
5 ECDSA signature = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C
076CD1BAAF47B8BBA6DCD78BCC64DFD3E80
E679D9A663CAE9E4D4C2C77023077CC549CE
4A61
6 UID of the IC = 045A115A346180
ECDSA Verification
7 Elliptic Curve Name = secp224r1
8 SEC1 Point Representation = 04
NXP Semiconductors AN12343
MIFARE DESFire Light Features and Hints
AN12343 All information provided in this document is subject to legal disclaimers. © NXP B.V. 2020. All rights reserved.
Application note Rev. 1.1 — 20 January 2020
COMPANY PUBLIC 522511 88 / 93
Step Command Data Message
9 Public Key point coordinate xD
 (28 bytes)
= 0E98E117AAA36457F43173DC920A8757267F44
CE4EC5ADD3C5407557
10 Public Key point coordinate yD
 (28 bytes)
= 1AEBBF7B942A9774A1D94AD02572427E5AE0A
2DD36591B1FB34FCF3D
11 Signature part 1 r = 1CA298FC3F0F04A329254AC0DF7A3EB8E756C
076CD1BAAF47B8BBA6D
12 Signature part 2 s = CD78BCC64DFD3E80E679D9A663CAE9E4D4C2
C77023077CC549CE4A61
13 ECDSA Verification
(Implementation or Cryptographic
Toolset)
= Signature valid

```


Access on Android through IsoDep technology

https://stackoverflow.com/questions/19589534/android-nfc-communication-with-mifare-desfire-ev1

https://stackoverflow.com/questions/25376914/access-mifare-desfire-card

https://stackoverflow.com/questions/11523765/how-well-does-the-android-nfc-api-support-mifare-desfire

Looks good - complete app: https://github.com/skjolber/desfire-tools-for-android

A research on how Metro de Madrid NFC cards works https://github.com/CRTM-NFC/Mifare-Desfire

HCE with DESFire EV1: https://github.com/piotrekwitkowski/LibraryNFC/

Reversed engineering commands: https://github.com/revk/DESFireAES/blob/master/DESFire.pdf



An article about DESFire usage: https://www.linkedin.com/pulse/mifare-desfire-introduction-david-coelho

See sample code in [Mifare DESFire An Introduction](Mifare DESFire An Introduction.md)

List of DESFire commands: https://github.com/jekkos/android-hce-desfire/blob/master/hceappletdesfire/src/main/java/net/jpeelaer/hce/desfire/DesFireInstruction.java

https://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/

https://github.com/codebutler/farebot/tree/master/farebot-card-desfire/src/main/java/com/codebutler/farebot/card/desfire

https://neteril.org/files/M075031_desfire.pdf

A lot of full commands and responds regarding DESFire: Mifare DESFire Light Features and Hints: https://www.nxp.com/docs/en/application-note/AN12343.pdf



## NTAG21x family

Some tag facts: Manufacturer programmed 7-byte UID for each device, Pre-programmed Capability container with one time programmable bits (NDEF), 
Field programmable read-only locking function, ECC based originality signature, 32-bit password protection to prevent unauthorized memory operations. 
The data is organized in pages of 4 byte of data each.

There are 3 tags available and the datasheet covers all of them NTAG213_215_216 : https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
1) NTAG213: Total memory 180 bytes
2) NTAG215: Total memory 540 bytes
3) NTAG216_ Total memory 924 bytes


All datasheets are available in the docs folder of this repository but it is always better to get one from the origin source.
