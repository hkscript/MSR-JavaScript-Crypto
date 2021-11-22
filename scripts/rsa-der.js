var rsaDer = (function () {
    var realAsn1Types = {
        INTEGER: 0x02,
        BITSTRING: 0x03,
        OBJECTIDENTIFIER: 0x06,
        SEQUENCE: 0x30
    };

    var flag = {
        NEED_FLAG_LEN: 0x80,
        ONE_BYTE_LEN_FLAG: 0x81,
        TWO_BYTE_LEN_FLAG: 0x82
    }

    var oidSeqDer = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

    function getLenDer(len) {
        if (len > 0xff) {
            return [flag.TWO_BYTE_LEN_FLAG, (len >> 8) & 0xff, len & 0xff]
        } else if (len >= flag.NEED_FLAG_LEN) {
            return [flag.ONE_BYTE_LEN_FLAG, len]
        } else {
            return [len]
        }
    }

    /**
     * 首个字节最高位不为0则填充一个0字节（确保符号位为0 正数）
     * @param {Array} i 
     */
    function lPadInteger(i) {
        if (i[0] >> 7) {
            return [0].concat(i)
        } else {
            return i;
        }
    }

    /**
     * 
     * 
30 82 01 22          ;SEQUENCE (0x122 bytes = 290 bytes)
|  30 0D             ;SEQUENCE (0x0d bytes = 13 bytes) 
|  |  06 09          ;OBJECT IDENTIFIER (0x09 = 9 bytes)
|  |  2A 86 48 86   
|  |  F7 0D 01 01 01 ;hex encoding of 1.2.840.113549.1.1
|  |  05 00          ;NULL (0 bytes)
|  03 82 01 0F 00    ;BIT STRING  (0x10f = 271 bytes)
|  |  30 82 01 0A       ;SEQUENCE (0x10a = 266 bytes)
|  |  |  02 82 01 01    ;INTEGER  (0x101 = 257 bytes)
|  |  |  |  00             ;leading zero of INTEGER
|  |  |  |  EB 50 63 99 F5 C6 12 F5  A6 7A 09 C1 19 2B 92 FA 
|  |  |  |  B5 3D B2 85 20 D8 59 CE  0E F6 B7 D8 3D 40 AA 1C 
|  |  |  |  1D CE 2C 07 20 D1 5A 0F  53 15 95 CA D8 1B A5 D1 
|  |  |  |  29 F9 1C C6 76 97 19 F1  43 58 72 C4 BC D0 52 11 
|  |  |  |  50 A0 26 3B 47 00 66 48  9B 91 8B FC A0 3C E8 A0
|  |  |  |  E9 FC 2C 03 14 C4 B0 96  EA 30 71 7C 03 C2 8C A2  
|  |  |  |  9E 67 8E 63 D7 8A CA 1E  9A 63 BD B1 26 1E E7 A0  
|  |  |  |  B0 41 AB 53 74 6D 68 B5  7B 68 BE F3 7B 71 38 28
|  |  |  |  38 C9 5D A8 55 78 41 A3  CA 58 10 9F 0B 4F 77 A5
|  |  |  |  E9 29 B1 A2 5D C2 D6 81  4C 55 DC 0F 81 CD 2F 4E 
|  |  |  |  5D B9 5E E7 0C 70 6F C0  2C 4F CA 35 8E A9 A8 2D 
|  |  |  |  80 43 A4 76 11 19 55 80  F8 94 58 E3 DA B5 59 2D
|  |  |  |  EF E0 6C DE 1E 51 6A 6C  61 ED 78 C1 39 77 AE 96 
|  |  |  |  60 A9 19 2C A7 5C D7 29  67 FD 3A FA FA 1F 1A 2F 
|  |  |  |  F6 32 5A 50 64 D8 47 02  8F 1E 6B 23 29 E8 57 2F 
|  |  |  |  36 E7 08 A5 49 DD A3 55  FC 74 A3 2F DD 8D BA 65
|  |  |  02 03          ;INTEGER (03 = 3 bytes)
|  |  |  |  010001
     *
     * @param {*} p 
     * @returns 
     */
    function exportKeyToSpki(p) {
        var n = lPadInteger(p.keyData.n)
        var e = lPadInteger(p.keyData.e)
        // 
        var nDer = [].concat(realAsn1Types.INTEGER, getLenDer(n.length), n)
        var eDer = [].concat(realAsn1Types.INTEGER, getLenDer(e.length), e)
        var keySequenceSeqDer = [].concat(realAsn1Types.SEQUENCE, getLenDer(nDer.length + eDer.length), nDer, eDer)

        var keySequenceSeqBitStringDer = [].concat(realAsn1Types.BITSTRING, getLenDer(keySequenceSeqDer.length + 1), [0], keySequenceSeqDer)

        var publicKeyInfoDer= [].concat(realAsn1Types.SEQUENCE,
            getLenDer(oidSeqDer.length + keySequenceSeqBitStringDer.length),
            oidSeqDer,
            keySequenceSeqBitStringDer
        );
        return new Uint8Array(publicKeyInfoDer).buffer
    }

    return {
        exportKeyToSpki: exportKeyToSpki
    };
})();
