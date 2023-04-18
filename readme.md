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

## Mifare Classic family

// for details see: https://android.googlesource.com/platform/frameworks/base/+/48a5ed5/core/java/android/nfc/tech/MifareClassic.java
// size could be 320 / SIZE_MINI, 1024 / SIZE_1K, 2048 / SIZE_2K or 4096 / SIZE_4K

Mifare Classic mini: Total memory 320 bytes, Get the datasheet MF1ICS20 here: http://www.orangetags.com/wp-content/downloads/datasheet/NXP/MF1ICS20.pdf

Mifare Classic 1K: Total memory 1024 bytes. Get the datasheet MF1S50yyX here: https://www.datasheetarchive.com/pdf/download.php?id=bee960138d6124d3df95eb5fbf45fb736c3438&type=P&term=MIFARE%2520Classic%2520Command

Mifare Classic 1K + 4K: Total memory 1024 and 4096 bytes. Get the datasheet  here: https://shop.sonmicro.com/Downloads/MIFARECLASSIC-UM.pdf

Mifare Classic EV1 1K: Total memory . Get the datasheet MF1S50YYX_V1 here: https://www.nxp.com/docs/en/data-sheet/MF1S50YYX_V1.pdf

Mifare Classic EV1 4K: Total memory . Get the datasheet MF1S70YYX_V1 here: https://www.nxp.com/docs/en/data-sheet/MF1S70YYX_V1.pdf


## Mifare Ultralight family

1) Mifare Ultralight: Total memory 64 bytes. Get the datasheet MF0ICU1 here: https://www.nxp.com/docs/en/data-sheet/MF0ICU1.pdf
2) Mifare Ultralight C: Total memory 192 bytes. Get the datasheet here MF0ICU2: https://www.nxp.com/docs/en/data-sheet/MF0ICU2.pdf
3) Mifare Ultralight EV1: Total memory 64 and 144 bytes. Get the datasheet here: https://www.nxp.com/docs/en/data-sheet/MF0ULX1.pdf

## Mifare DESFire EV1 family

There are 3 tags available and the datasheet covers all of them MF3ICDx21_41_81 : https://www.nxp.com/docs/en/data-sheet/MF3ICDX21_41_81_SDS.pdf

https://www.linkedin.com/pulse/mifare-desfire-introduction-david-coelho

See sample code in [Mifare DESFire An Introduction](Mifare DESFire An Introduction.md)

## NTAG21x family

There are 3 tags available and the datasheet covers all of them NTAG213_215_216 : https://www.nxp.com/docs/en/data-sheet/NTAG213_215_216.pdf
1) NTAG213: Total memory 180 bytes
2) NTAG215: Total memory 540 bytes
3) NTAG216_ Total memory 924 bytes


All datasheets are available in the docs folder of this repository but it is always better to get one from the origin source.
