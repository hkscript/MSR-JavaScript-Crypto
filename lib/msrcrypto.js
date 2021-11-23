//*******************************************************************************
//
//    Copyright 2020 Microsoft
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
//
//*******************************************************************************
"use strict";

var msrCryptoVersion = "1.6.4";

(function(root, factory) {

    if (typeof define === "function" && define.amd) {
        define([], function() {
            return (root.msrCrypto = factory(root));
        });
    } else if (typeof exports === "object") {
        module.exports = factory(root);
    } else {
        root.msrCrypto = factory(root);
    }

}(this, function(global) {

    global = global || {};

    var msrCrypto = function() {

        var operations = {};

        operations.register = function(operationType, algorithmName, functionToCall) {

            if (!operations[operationType]) {
                operations[operationType] = {};
            }

            var op = operations[operationType];

            if (!op[algorithmName]) {
                op[algorithmName] = functionToCall;
            }

        };

        operations.exists = function(operationType, algorithmName) {
            if (!operations[operationType]) {
                return false;
            }

            return operations[operationType][algorithmName] ? true : false;
        };

        var scriptUrl = (function() {

            if (typeof document !== "undefined") {
                try {
                    throw new Error();
                } catch (e) {
                    if (e.stack) {
                        var match = /\w+:\/\/(.+?\/)*.+\.js/.exec(e.stack);
                        return (match && match.length > 0) ? match[0] : null;
                    }
                }
            } else if (typeof self !== "undefined") {
                return self.location.href;
            }

            return null;

        })();

        var fprngEntropyProvided = false;

        var webWorkerSupport = (typeof Worker !== "undefined");

        var runningInWorkerInstance = typeof importScripts === "function" && self instanceof WorkerGlobalScope;

        var workerInitialized = false;

        var typedArraySupport = (typeof ArrayBuffer !== "undefined");

        var setterSupport = (function() {
            try {
                Object.defineProperty({}, "oncomplete", {});
                return true;
            } catch (ex) {
                return false;
            }
        }());

        var asyncMode = false;

        var createProperty = function(parentObject, propertyName, initialValue, getterFunction, setterFunction) {
            if (!setterSupport) {
                parentObject[propertyName] = initialValue;
                return;
            }

            var setGet = {};

            getterFunction && (setGet.get = getterFunction);
            setterFunction && (setGet.set = setterFunction);

            Object.defineProperty(
                parentObject,
                propertyName, setGet);
        };

        var msrcryptoHashFunctions = {};

        var msrcryptoUtilities = (function() {

            var encodingChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

            function consoleLog(text) {
                if ("console" in self && "log" in console) {
                    console.log(text);
                }
            }

            function toBase64(data, base64Url) {
                var dataType = getObjectType(data);

                if (dataType !== "Array" && dataType !== "Uint8Array" && dataType !== "ArrayBuffer") {
                    throw new Error("invalid input");
                }

                var output = "";
                var input = toArray(data);

                if (!base64Url) {
                    base64Url = false;
                }

                var char1, char2, char3, enc1, enc2, enc3, enc4;
                var i;

                for (i = 0; i < input.length; i += 3) {

                    char1 = input[i];
                    char2 = input[i + 1];
                    char3 = input[i + 2];

                    enc1 = char1 >> 2;
                    enc2 = ((char1 & 0x3) << 4) | (char2 >> 4);
                    enc3 = ((char2 & 0xF) << 2) | (char3 >> 6);
                    enc4 = char3 & 0x3F;

                    if (isNaN(char2)) {
                        enc3 = enc4 = 64;

                    } else if (isNaN(char3)) {
                        enc4 = 64;
                    }

                    output = output +
                        encodingChars.charAt(enc1) +
                        encodingChars.charAt(enc2) +
                        encodingChars.charAt(enc3) +
                        encodingChars.charAt(enc4);

                }

                if (base64Url) {
                    return output.replace(/\+/g, "-").replace(/\//g, "_").replace(/\=/g, "");
                }

                return output;
            }

            function base64ToBytes(encodedString) {
                encodedString = encodedString.replace(/-/g, "+").replace(/_/g, "/");

                while (encodedString.length % 4 !== 0) {
                    encodedString += "=";
                }

                var output = [];
                var char1, char2, char3;
                var enc1, enc2, enc3, enc4;
                var i;

                encodedString = encodedString.replace(/[^A-Za-z0-9\+\/\=]/g, "");

                for (i = 0; i < encodedString.length; i += 4) {

                    enc1 = encodingChars.indexOf(encodedString.charAt(i));
                    enc2 = encodingChars.indexOf(encodedString.charAt(i + 1));
                    enc3 = encodingChars.indexOf(encodedString.charAt(i + 2));
                    enc4 = encodingChars.indexOf(encodedString.charAt(i + 3));

                    char1 = (enc1 << 2) | (enc2 >> 4);
                    char2 = ((enc2 & 15) << 4) | (enc3 >> 2);
                    char3 = ((enc3 & 3) << 6) | enc4;

                    output.push(char1);

                    if (enc3 !== 64) {
                        output.push(char2);
                    }

                    if (enc4 !== 64) {
                        output.push(char3);
                    }

                }

                return output;

            }

            function getObjectType(object) {
                return Object.prototype.toString.call(object).slice(8, -1);
            }

            function bytesToHexString(bytes, separate) {
                var result = "";
                if (typeof separate === "undefined") {
                    separate = false;
                }

                for (var i = 0; i < bytes.length; i++) {

                    if (separate && (i % 4 === 0) && i !== 0) {
                        result += "-";
                    }

                    var hexval = bytes[i].toString(16).toUpperCase();
                    if (hexval.length === 1) {
                        result += "0";
                    }

                    result += hexval;
                }

                return result;
            }

            function bytesToInt32(bytes, index) {
                index = (index || 0);

                return (bytes[index] << 24) |
                    (bytes[index + 1] << 16) |
                    (bytes[index + 2] << 8) |
                    bytes[index + 3];
            }

            function hexToBytesArray(hexString) {
                hexString = hexString.replace(/\-/g, "");

                var result = [];
                while (hexString.length >= 2) {
                    result.push(parseInt(hexString.substring(0, 2), 16));
                    hexString = hexString.substring(2, hexString.length);
                }

                return result;
            }

            function clone(object) {
                var newObject = {};
                for (var propertyName in object) {
                    if (object.hasOwnProperty(propertyName)) {
                        newObject[propertyName] = object[propertyName];
                    }
                }
                return newObject;
            }

            function unpackData(base64String, arraySize, toUint32s) {
                var bytes = base64ToBytes(base64String),
                    data = [],
                    i;

                if (isNaN(arraySize)) {
                    return bytes;
                } else {
                    for (i = 0; i < bytes.length; i += arraySize) {
                        data.push(bytes.slice(i, i + arraySize));
                    }
                }

                if (toUint32s) {
                    for (i = 0; i < data.length; i++) {
                        data[i] = (data[i][0] << 24) + (data[i][1] << 16) + (data[i][2] << 8) + data[i][3];
                    }
                }

                return data;
            }

            function int32ToBytes(int32) {
                return [(int32 >>> 24) & 255, (int32 >>> 16) & 255, (int32 >>> 8) & 255, int32 & 255];
            }

            function int32ArrayToBytes(int32Array) {
                var result = [];
                for (var i = 0; i < int32Array.length; i++) {
                    result = result.concat(int32ToBytes(int32Array[i]));
                }
                return result;
            }

            function xorVectors(a, b, res) {
                var length = Math.min(a.length, b.length),
                    res = res || new Array(length);
                for (var i = 0; i < length; i += 1) {
                    res[i] = a[i] ^ b[i];
                }
                return res;
            }

            function getVector(length, fillValue) {
                if (isNaN(fillValue)) {
                    fillValue = 0;
                }

                var res = new Array(length);
                for (var i = 0; i < length; i += 1) {
                    res[i] = fillValue;
                }
                return res;
            }

            function toArray(typedArray) {
                if (!typedArray) {
                    return [];
                }

                if (typedArray.pop) {
                    return typedArray;
                }

                if (getObjectType(typedArray) === "ArrayBuffer") {
                    typedArray = new Uint8Array(typedArray);
                } else if (typedArray.BYTES_PER_ELEMENT > 1) {
                    typedArray = new Uint8Array(typedArray.buffer);
                }

                if (typedArray.length === 1) {
                    return [typedArray[0]];
                }

                if (typedArray.length < 65536) {
                    return Array.apply(null, typedArray);
                }

                var returnArray = new Array(typedArray.length);
                for (var i = 0; i < typedArray.length; i++) {
                    returnArray[i] = typedArray[i];
                }

                return returnArray;

            }

            function padEnd(array, value, finalLength) {
                while (array.length < finalLength) {
                    array.push(value);
                }

                return array;
            }

            function padFront(array, value, finalLength) {
                while (array.length < finalLength) {
                    array.unshift(value);
                }

                return array;
            }

            function arraysEqual(array1, array2) {
                var result = true;

                if (array1.length !== array2.length) {
                    result = false;
                }

                for (var i = 0; i < array1.length; i++) {
                    if (array1[i] !== array2[i]) {
                        result = false;
                    }
                }

                return result;
            }

            function verifyByteArray(array) {
                if (getObjectType(array) !== "Array") {
                    return false;
                }

                var element;

                for (var i = 0; i < array.length; i++) {

                    element = array[i];

                    if (isNaN(element) || element < 0 || element > 255) {
                        return false;
                    }
                }

                return true;
            }

            function checkParam(param, type, errorMessage) {

                if (!param) {
                    throw new Error(errorMessage);
                }

                if (type && (getObjectType(param) !== type)) {
                    throw new Error(errorMessage);
                }

                return true;
            }

            function stringToBytes(text) {
                var encodedBytes = [];

                for (var i = 0, j = 0; i < text.length; i++) {

                    var charCode = text.charCodeAt(i);

                    if (charCode < 128) {
                        encodedBytes[j++] = charCode;

                    } else if (charCode < 2048) {
                        encodedBytes[j++] = (charCode >>> 6) | 192;
                        encodedBytes[j++] = (charCode & 63) | 128;

                    } else if (charCode < 0xD800 || charCode > 0xDFFF) {
                        encodedBytes[j++] = (charCode >>> 12) | 224;
                        encodedBytes[j++] = ((charCode >>> 6) & 63) | 128;
                        encodedBytes[j++] = (charCode & 63) | 128;

                    } else {
                        charCode = ((charCode - 0xD800) * 0x400) + (text.charCodeAt(++i) - 0xDC00) + 0x10000;
                        encodedBytes[j++] = (charCode >>> 18) | 240;
                        encodedBytes[j++] = ((charCode >>> 12) & 63) | 128;
                        encodedBytes[j++] = (charCode >>> 6) & 63 | 128;
                        encodedBytes[j++] = (charCode & 63) | 128;
                    }
                }

                return encodedBytes;
            }

            function bytesToString(textBytes) {
                var result = "",
                    charCode;

                textBytes = toArray(textBytes);

                for (var i = 0; i < textBytes.length;) {

                    var encodedChar = textBytes[i++];

                    if (encodedChar < 128) {
                        charCode = encodedChar;

                    } else if (encodedChar < 224) {
                        charCode = (encodedChar << 6) + textBytes[i++] - 0x3080;

                    } else if (encodedChar < 240) {
                        charCode =
                            (encodedChar << 12) + (textBytes[i++] << 6) + textBytes[i++] - 0xE2080;

                    } else {
                        charCode =
                            (encodedChar << 18) + (textBytes[i++] << 12) + (textBytes[i++] << 6) + textBytes[i++] - 0x3C82080;
                    }

                    if (charCode > 0xFFFF) {
                        var surrogateHigh = Math.floor((charCode - 0x10000) / 0x400) + 0xD800;
                        var surrogateLow = ((charCode - 0x10000) % 0x400) + 0xDC00;
                        result += String.fromCharCode(surrogateHigh, surrogateLow);
                        continue;
                    }

                    result += String.fromCharCode(charCode);
                }

                return result;
            }

            return {
                consoleLog: consoleLog,
                toBase64: toBase64,
                fromBase64: base64ToBytes,
                checkParam: checkParam,
                getObjectType: getObjectType,
                bytesToHexString: bytesToHexString,
                bytesToInt32: bytesToInt32,
                stringToBytes: stringToBytes,
                bytesToString: bytesToString,
                unpackData: unpackData,
                hexToBytesArray: hexToBytesArray,
                int32ToBytes: int32ToBytes,
                int32ArrayToBytes: int32ArrayToBytes,
                toArray: toArray,
                arraysEqual: arraysEqual,
                clone: clone,
                xorVectors: xorVectors,
                padEnd: padEnd,
                padFront: padFront,
                getVector: getVector,
                verifyByteArray: verifyByteArray
            };

        })();

        var asn1 = (function() {

            var asn1Types = {
                0x00: "CUSTOM",
                0x01: "BOOLEAN",
                0x02: "INTEGER",
                0x03: "BIT STRING",
                0x04: "OCTET STRING",
                0x05: "NULL",
                0x06: "OBJECT IDENTIFIER",
                0x10: "SEQUENCE",
                0x11: "SET",
                0x13: "PRINTABLE STRING",
                0x17: "UTCTime"
            };

            var asn1Classes = {
                0x00: "UNIVERSAL",
                0x01: "APPLICATION",
                0x02: "Context-Defined",
                0x03: "PRIVATE"
            };

            function parse(bytes, force) {

                force = !!force;

                var type = asn1Types[bytes[0] & 0x1F],
                    dataLen = bytes[1],
                    i = 0,
                    constructed = !!(bytes[0] & 0x20),
                    remainder,
                    child,
                    header;

                if (dataLen & 0x80) {
                    for (i = 0, dataLen = 0; i < (bytes[1] & 127); i++) {
                        dataLen = (dataLen << 8) + bytes[2 + i];
                    }
                }

                header = 2 + i;

                if (type === undefined || dataLen > bytes.length) {
                    return null;
                }

                var obj = constructed ? [] : {};

                obj.type = type;
                obj.header = header;
                obj.data = bytes.slice(0, dataLen + header);
                if (constructed || force) {
                    if (obj.type === "BIT STRING" && bytes[header] === 0) {
                        i++;
                    }
                    remainder = bytes.slice(header, obj.data.length);
                    while (remainder.length > 0) {
                        child = parse(remainder);
                        if (child === null) {
                            break;
                        }
                        obj.push(child);
                        remainder = remainder.slice(child.data.length);
                    }
                }
                return obj;
            }

            function encode(asn1tree) {

                throw new Error("not implemented");
            }

            function toString(objTree, indent) {

                var output = new Array(indent + 1).join(" ") + objTree.type + " (" + objTree.length + ") " + bytesToHexString(objTree.data).substring(0, 16) + "\n";

                if (!objTree.children) {
                    return output;
                }

                for (var i = 0; i < objTree.children.length; i++) {
                    output += toString(objTree.children[i], indent + 4) + "";
                }

                return output;
            }

            return {
                parse: parse,
                encode: encode,
                toString: function(objTree) {
                    return toString(objTree, 0);
                }
            };

        })();

        var msrcryptoWorker = (function() {

            function returnResult(result) {

                if (workerInitialized && runningInWorkerInstance) {
                    self.postMessage(result);
                }
                return result;
            }

            var workerId,
                operationType,
                operationSubType;

            return {

                jsCryptoRunner: function(e) {

                    workerId = e.data.workerid;
                    operationType = e.data.operationType;
                    operationSubType = e.data.operationSubType;

                    var operation = e.data.operationType,
                        result,
                        func = operations[operation][e.data.algorithm.name],
                        p = e.data;

                    if (!operations.exists(operation, e.data.algorithm.name)) {
                        throw new Error("unregistered algorithm.");
                    }

                    if (p.operationSubType) {
                        result = returnResult({
                            type: p.operationSubType,
                            result: func(p)
                        });
                    } else {
                        result = returnResult(func(p));
                    }

                    return result;
                },

                returnResult: returnResult
            };

        })();

        if (runningInWorkerInstance) {

            self.onmessage = function(e) {

                if (!workerInitialized && e.data.prngSeed) {
                    var entropy = e.data.prngSeed;
                    msrcryptoPseudoRandom.init(entropy);
                    workerInitialized = true;
                    return msrcryptoWorker.returnResult({
                        initialized: true
                    });
                }

                if (workerInitialized === true) {
                    msrcryptoWorker.jsCryptoRunner(e);
                }

            };
        }

        var msrcryptoJwk = (function() {

            var utils = msrcryptoUtilities;

            function stringToArray(stringData) {

                var result = [];

                for (var i = 0; i < stringData.length; i++) {
                    result[i] = stringData.charCodeAt(i);
                }

                if (result[result.length - 1] === 0) {
                    result.pop();
                }

                return result;
            }

            function getKeyType(keyHandle) {

                var algType = keyHandle.algorithm.name.slice(0, 3).toUpperCase();

                if (algType === "RSA") {
                    return "RSA";
                }

                if (algType === "ECD") {
                    return "EC";
                }

                return "oct";
            }

            function hashSize(algorithm) {
                return algorithm.hash.name.substring(algorithm.hash.name.indexOf("-") + 1);
            }

            var algorithmMap = {

                "HMAC": function(algorithm) {
                    return "HS" + hashSize(algorithm);
                },

                "AES-CBC": function(algorithm) {
                    return "A" + algorithm.length.toString() + "CBC";
                },

                "AES-GCM": function(algorithm) {
                    return "A" + algorithm.length.toString() + "GCM";
                },

                "RSAES-PKCS1-V1_5": function(algorithm) {
                    return "RSA1_5";
                },

                "RSASSA-PKCS1-V1_5": function(algorithm) {
                    return "RS" + hashSize(algorithm);
                },

                "RSA-OAEP": function(algorithm) {
                    if (algorithm.hash.name.toUpperCase() === "SHA-1") {
                        return "RSA-OAEP";
                    }
                    return "RSA-OAEP-" + hashSize(algorithm);
                },

                "RSA-PSS": function(algorithm) {
                    return "PS" + hashSize(algorithm);
                },

                "ECDSA": function(algorithm) {
                    return "EC-" + algorithm.namedCurve.substring(algorithm.namedCurve.indexOf("-") + 1);
                }
            };

            function keyToJwk(keyHandle, keyData) {

                var key = {};

                key.kty = getKeyType(keyHandle);
                key.ext = keyHandle.extractable;
                if (algorithmMap[keyHandle.algorithm.name.toUpperCase()]) {
                    key.alg = algorithmMap[keyHandle.algorithm.name.toUpperCase()](keyHandle.algorithm);
                }
                key.key_ops = keyHandle.usages;
                if (keyData.pop) {
                    key.k = utils.toBase64(keyData, true);
                } else {
                    for (var property in keyData) {
                        if (keyData[property].pop && property !== "key_ops") {
                            key[property] = utils.toBase64(keyData[property], true);
                        }
                    }
                }

                if (keyHandle.algorithm.namedCurve) {
                    key.crv = keyHandle.algorithm.namedCurve;
                }

                return key;
            }

            function findUsage(usage, usages) {
                for (var i = 0; i < usages.length; i++) {
                    if (usage.toUpperCase() === usages[i].toUpperCase()) {
                        return true;
                    }
                }
                return false;
            }

            function keyToJwkOld(keyHandle, keyData) {

                var key = {};

                key.kty = getKeyType(keyHandle);
                key.extractable = keyHandle.extractable;

                if (keyData.pop) {
                    key.k = utils.toBase64(keyData, true);
                } else {
                    for (var property in keyData) {
                        if (keyData[property].pop) {
                            key[property] = utils.toBase64(keyData[property], true);
                        }
                    }
                }

                if (keyHandle.algorithm.namedCurve) {
                    key.crv = keyHandle.algorithm.namedCurve;
                }

                var stringData = JSON.stringify(key, null, "\t");

                return stringToArray(stringData);
            }

            function jwkToKey(keyData, algorithm, propsToArray) {
                var jsonKeyObject = JSON.parse(JSON.stringify(keyData));

                for (var i = 0; i < propsToArray.length; i += 1) {
                    var propValue = jsonKeyObject[propsToArray[i]];
                    if (propValue) {
                        jsonKeyObject[propsToArray[i]] =
                            utils.fromBase64(propValue);
                    }
                }

                return jsonKeyObject;
            }

            return {
                keyToJwkOld: keyToJwkOld,
                keyToJwk: keyToJwk,
                jwkToKey: jwkToKey
            };
        })();

        function msrcryptoMath() {
            var DIGIT_BITS = 24;
            var DIGIT_NUM_BYTES = Math.floor(DIGIT_BITS / 8);
            var DIGIT_MASK = (1 << DIGIT_BITS) - 1;
            var DIGIT_BASE = (1 << DIGIT_BITS);
            var DIGIT_MAX = DIGIT_MASK;
            var DIG_INV = 1 / DIGIT_BASE;
            var DIGIT_MAX_ADDS = 31;

            var DIGIT_SCALER = [1, 256];
            for (var ds = 2; ds <= DIGIT_NUM_BYTES; ds++) {
                DIGIT_SCALER[ds] = DIGIT_SCALER[ds - 1] * 256;
            }

            var Zero = [0];
            var One = [1];

            function createArray(parameter) {
                var i, array = null;
                if (!arguments.length || typeof arguments[0] === "number") {
                    array = new Array(parameter);
                    for (i = 0; i < parameter; i += 1) {
                        array[i] = 0;
                    }
                } else if (typeof arguments[0] === "object") {
                    array = new Array(parameter.length);
                    for (i = 0; i < parameter.length; i += 1) {
                        array[i] = parameter[i];
                    }
                }
                return array;
            }

            function stringToDigits(numberStr, radix) {
                numberStr = numberStr.replace(/^\s+|\s+$/g, "");
                var num = [0];
                var buffer = [0];
                radix = radix || 10;
                for (var i = 0; i < numberStr.length; i += 1) {
                    var char = parseInt(numberStr[i], radix);
                    if (isNaN(char)) {
                        throw new Error("Failed to convert string to integer in radix " + radix.toString());
                    }

                    multiply(num, radix, buffer);

                    add(buffer, [char], num);
                    normalizeDigitArray(num);
                }

                return num;
            }

            function digitsToString(digits, radix) {
                radix = radix || 10;
                if (DIGIT_BASE <= radix) {
                    throw new Error("DIGIT_BASE is smaller than RADIX; cannot convert.");
                }

                var wordLength = digits.length;
                var quotient = [];
                var remainder = [];
                var temp1 = [];
                var temp2 = [];
                var divisor = [];
                var a = [];
                var i;

                var sb = "";
                var pad = "0";
                divisor[0] = radix;
                while (Math.floor(DIGIT_BASE / divisor[0]) >= radix) {
                    divisor[0] = divisor[0] * radix;
                    pad = pad.concat("0");
                }

                for (i = 0; i < wordLength; i += 1) {
                    a[i] = digits[i];
                }

                do {
                    var allZeros = true;
                    for (i = 0; i < a.length; i += 1) {
                        if (a[i] !== 0) {
                            allZeros = false;
                            break;
                        }
                    }

                    if (allZeros) {
                        break;
                    }

                    divRem(a, divisor, quotient, remainder, temp1, temp2);
                    normalizeDigitArray(quotient, a.length, true);

                    var newDigits = remainder[0].toString(radix);
                    sb = pad.substring(0, pad.length - newDigits.length) + newDigits + sb;

                    var swap = a;
                    a = quotient;
                    quotient = swap;
                } while (true);

                while (sb.length !== 0 && sb[0] === "0") {
                    sb = sb.substring(1, sb.length);
                }

                if (sb.length === 0) {
                    sb = "0";
                }

                return sb;
            }

            function computeBitArray(bytes) {
                var out = createArray(bytes.length * 8);
                var bitLength = 0;
                var i = bytes.length - 1;
                while (i >= 0) {
                    var j = 0;
                    while (j < 8) {
                        var mask = (1 << j);
                        var bit = ((bytes[i] & mask) === mask) ? 1 : 0;
                        var thisBitIndex = (8 * ((bytes.length - i) - 1)) + j;

                        if (bit === 1) {
                            bitLength = thisBitIndex + 1;
                        }

                        out[thisBitIndex] = bit;
                        j += 1;
                    }

                    i--;
                }

                return out.slice(0, bitLength);
            }

            function bitScanForward(digit) {
                var index = 0;

                for (var i = 0; i < DIGIT_BITS; i++) {
                    index = Math.max(index, -(digit >>> i & 1) & i);
                }

                return index;
            }

            function highestSetBit(bytes) {
                var i = 0;
                var bitLength = 0;

                while (i < bytes.length) {
                    if (bitLength === 0) {
                        var j = 7;
                        while (j >= 0 && bitLength === 0) {
                            var mask = (1 << j);
                            if ((bytes[i] & mask) === mask) {
                                bitLength = j + 1;
                            }

                            j--;
                        }
                    } else {
                        bitLength += 8;
                    }

                    i += 1;
                }

                return bitLength;
            }

            function fixedWindowRecode(digits, windowSize, t) {
                digits = digits.slice();

                var recodedDigits = [],
                    windowSizeBits = Math.pow(2, windowSize),
                    windowSizeMinus1Bits = Math.pow(2, windowSize - 1);

                for (var i = 0; i < t; i++) {

                    recodedDigits[i] = (digits[0] % windowSizeBits) - windowSizeMinus1Bits;

                    digits[0] = digits[0] - recodedDigits[i];

                    cryptoMath.shiftRight(digits, digits, windowSize - 1);
                }

                recodedDigits[i] = digits[0];

                return recodedDigits;
            }

            function fixedWindowRecode2(digits, windowSize) {

                var digLen = digits.length,
                    bits = new Array(digLen * DIGIT_BITS),
                    i = 0,
                    j = 0,
                    k = 0,
                    r = 0,
                    dig,
                    result = new Array(Math.ceil(digLen * DIGIT_BITS / windowSize));

                for (k = 0, result[0] = 0; i < digLen; i++) {
                    for (j = 0, dig = digits[i]; j < DIGIT_BITS; j++, dig >>>= 1) {
                        if (k === windowSize) {
                            result[++r] = 0;
                            k = 0;
                        }
                        result[r] += (dig & 1) << k++;
                    }
                }

                return result;
            }

            function fetchBits(digits, startBit, count) {
                var startDigit = Math.floor(startBit / cryptoMath.DIGIT_BITS);
                var endDigit = startDigit + 1;

                var shiftRight = (startBit % cryptoMath.DIGIT_BITS);
                var shiftLeft = cryptoMath.DIGIT_BITS - shiftRight;

                var bits = (digits[startDigit] >>> shiftRight) | (digits[endDigit] << shiftLeft);

                return bits & (cryptoMath.DIGIT_MASK >>> (cryptoMath.DIGIT_BITS - count));

            }

            function fetchBits2(digits, startBit, count) {
                var startDigit = Math.floor(startBit / DIGIT_BITS),
                    shiftRight = (startBit % DIGIT_BITS);

                return (digits[startDigit] >>> shiftRight) |
                    (digits[startDigit + 1] << (DIGIT_BITS - shiftRight)) &
                    (DIGIT_MASK >>> (DIGIT_BITS - count));
            }

            function copyArray(source, sourceIndex, destination, destIndex, length) {
                while (length-- > 0) {
                    destination[destIndex + length] = source[sourceIndex + length];
                }
            }

            function isZero(array) {
                var i,
                    result = 0;

                for (i = 0; i < array.length; i += 1) {
                    result = result | array[i];
                }
                return !result;
            }

            function isEven(array) {
                return (array[0] & 0x1) === 0x0;
            }

            function sequenceEqual(left, right) {
                var equal = left.length === right.length;

                for (var i = 0; i < Math.min(left.length, right.length); i += 1) {
                    if (left[i] !== right[i]) {
                        equal = false;
                    }
                }

                return equal;
            }

            function bytesToDigits(bytes) {
                var arrayLength = Math.floor((bytes.length + DIGIT_NUM_BYTES - 1) / DIGIT_NUM_BYTES);
                var array = new Array(arrayLength);
                array[0] = 0;
                var digit = 0,
                    index = 0,
                    scIndex = 0;
                for (var i = bytes.length - 1; i >= 0; i--) {
                    digit = digit + (DIGIT_SCALER[scIndex++] * (bytes[i] & 0x0ff));
                    if (DIGIT_SCALER[scIndex] === DIGIT_BASE) {
                        scIndex = 0;
                        array[index++] = digit;
                        digit = 0;
                    }
                }

                if (digit !== 0) {
                    array[index] = digit;
                }

                while (array[--arrayLength] == null) {
                    array[arrayLength] = 0;
                }

                return array;
            }

            function digitsToBytes(digits, trim, minTrimLength) {
                var i, j, byte1;
                var bytes = [0];

                if (typeof trim === "undefined") {
                    trim = true;
                }

                for (i = 0; i < digits.length; i += 1) {
                    byte1 = digits[i];
                    for (j = 0; j < DIGIT_NUM_BYTES; j += 1) {
                        bytes[i * DIGIT_NUM_BYTES + j] = byte1 & 0x0FF;
                        byte1 = Math.floor(byte1 / 256);
                    }
                }

                bytes.reverse();

                if (minTrimLength === undefined) {
                    minTrimLength = 1;
                }
                if (trim) {
                    while (bytes.length > minTrimLength && bytes[0] === 0) {
                        bytes.shift();
                    }
                }

                return bytes;
            }

            function intToDigits(value, numDigits) {
                if (typeof numDigits === "undefined") {
                    if (value <= 1) {
                        numDigits = 1;
                    } else {
                        var numBits = Math.log(value) / Math.LN2;
                        numDigits = Math.ceil(numBits / DIGIT_BITS);
                    }
                }

                var digitRepresentation = [];
                while (value > 0) {
                    digitRepresentation.push(value % DIGIT_BASE);
                    value = Math.floor(value / DIGIT_BASE);
                }

                while (digitRepresentation.length < numDigits) {
                    digitRepresentation.push(0);
                }

                return digitRepresentation;
            }

            function mswIndex(digits) {
                for (var i = digits.length - 1; i >= 0; i--) {
                    if (digits[i] !== undefined && digits[i] !== 0) {
                        return i;
                    }
                }

                return (digits[0] === 0) ? -1 : 0;
            }

            function compareDigits(left, right) {

                var result = 0,
                    val, i;

                for (i = 0; i < Math.max(left.length, right.length); i++) {
                    val = ~~left[i] - ~~right[i];
                    result = val + (result & -!val);
                }

                return result;
            }

            function normalizeDigitArray(digits, length, pad) {
                var i = mswIndex(digits);

                digits.length = length || i + 1;

                if (pad) {
                    while (++i < digits.length) {
                        digits[i] = 0;
                    }
                }

                if (digits.length <= 0) {
                    digits[0] = 0;
                    digits.length = 1;
                }

                return digits;
            }

            function shiftRight(source, destination, bits, length) {
                if (bits === undefined) {
                    bits = 1;
                } else if (bits >= DIGIT_BITS || bits < 0) {
                    throw new Error("Invalid bit count for shiftRight");
                }
                if (length === undefined) {
                    length = source.length;
                }

                var n = length - 1;
                var leftShiftBitCount = DIGIT_BITS - bits;
                for (var i = 0; i < n; i++) {
                    destination[i] = ((source[i + 1] << leftShiftBitCount) | (source[i] >>> bits)) & DIGIT_MASK;
                }

                destination[n] = source[n] >>> bits;
            }

            function shiftLeft(source, destination, bits, length) {
                if (bits === undefined) {
                    bits = 1;
                } else if (bits >= DIGIT_BITS || bits < 0) {
                    throw new Error("bit count must be smaller than DIGIT_BITS and positive in shiftLeft");
                }
                if (length === undefined) {
                    length = source.length;
                }

                var rightShiftBitCount = DIGIT_BITS - bits;
                destination[length] = (source[length - 1] >>> (DIGIT_BITS - bits)) || destination[length];
                for (var i = length - 1; i > 0; i--) {
                    destination[i] = ((source[i] << bits) | ((source[i - 1] >>> rightShiftBitCount))) & DIGIT_MASK;
                }

                destination[0] = (source[0] << bits) & DIGIT_MASK;
            }

            function add(addend1, addend2, sum) {
                var shortArray = addend1;
                var longArray = addend2;
                if (addend2.length < addend1.length) {
                    shortArray = addend2;
                    longArray = addend1;
                }

                var s = shortArray.length;
                var carry = 0;
                var i;

                for (i = 0; i < s; i += 1) {
                    carry += shortArray[i] + longArray[i];
                    sum[i] = carry & DIGIT_MASK;
                    carry = (carry >> DIGIT_BITS);
                }

                for (i = s; i < longArray.length; i += 1) {
                    carry += longArray[i];
                    sum[i] = carry & DIGIT_MASK;
                    carry = (carry >> DIGIT_BITS);
                }

                sum.length = longArray.length;

                if (carry !== 0) {
                    sum[i] = carry & DIGIT_MASK;
                }

                return carry;
            }

            function subtract(minuend, subtrahend, difference) {
                var s = subtrahend.length;
                if (minuend.length < subtrahend.length) {
                    s = mswIndex(subtrahend) + 1;
                    if (minuend.length < s) {
                        throw new Error("Subtrahend is longer than minuend, not supported.");
                    }
                }
                var i, carry = 0;
                for (i = 0; i < s; i += 1) {
                    carry += minuend[i] - subtrahend[i];
                    difference[i] = carry & DIGIT_MASK;
                    carry = carry >> DIGIT_BITS;
                }

                while (i < minuend.length) {
                    carry += minuend[i];
                    difference[i++] = carry & DIGIT_MASK;
                    carry = carry >> DIGIT_BITS;
                }

                return carry;
            }

            function multiply(a, b, p) {

                b = (typeof b === "number") ? [b] : b;

                var i, j, k, l, c, t1, t2, alen = a.length,
                    blen = b.length,
                    bi;

                for (i = 0; i < alen + blen; i += 1) {
                    p[i] = 0;
                }

                i = 0;
                l = 0;

                var maxRounds = 31;
                var ks = 0;

                while (i < blen) {

                    l = Math.min(l + maxRounds, blen);

                    for (; i < l; i++) {
                        bi = b[i];
                        for (j = 0; j < alen; j++) {
                            p[i + j] += a[j] * bi;
                        }
                    }

                    c = 0;
                    for (k = ks; k < i + alen; k++) {
                        t1 = p[k] + c;
                        t2 = t1 & DIGIT_MASK;
                        p[k] = t2;
                        c = (t1 - t2) * DIG_INV;
                    }
                    p[k] = c;

                    ks += maxRounds;
                }

                p.length = alen + blen;

                return p;
            }

            function divRem(dividend, divisor, quotient, remainder, temp1, temp2) {
                var m = mswIndex(dividend) + 1;
                var n = mswIndex(divisor) + 1;
                var qhat, rhat, carry, p, t, i, j;

                if (m < n) {
                    copyArray(dividend, 0, remainder, 0, dividend.length);
                    remainder.length = dividend.length;
                    normalizeDigitArray(remainder);
                    quotient[0] = 0;
                    quotient.length = 1;
                    return;
                } else if (n === 0 || (n === 1 && divisor[n - 1] === 0)) {
                    throw new Error("Division by zero.");
                } else if (n === 1) {
                    t = divisor[0];
                    rhat = 0;
                    for (j = m - 1; j >= 0; j--) {
                        p = (rhat * DIGIT_BASE) + dividend[j];
                        quotient[j] = (p / t) & DIGIT_MASK;
                        rhat = (p - quotient[j] * t) & DIGIT_MASK;
                    }
                    quotient.length = m;
                    normalizeDigitArray(quotient);
                    remainder[0] = rhat;
                    remainder.length = 1;
                    return;
                }

                var s = DIGIT_BITS - 1 - bitScanForward(divisor[n - 1]);
                var vn = temp1 || [];
                vn.length = n;
                shiftLeft(divisor, vn, s, n);

                var un = temp2 || [];
                un.length = m;
                shiftLeft(dividend, un, s, m);
                un[m] = un[m] || 0;

                quotient.length = m - n + 1;
                remainder.length = n;
                for (j = m - n; j >= 0; j--) {
                    qhat = Math.floor((un[j + n] * DIGIT_BASE + un[j + n - 1]) / vn[n - 1]);
                    rhat = (un[j + n] * DIGIT_BASE + un[j + n - 1]) - qhat * vn[n - 1];

                    while (true) {
                        if (qhat >= DIGIT_BASE || (qhat * vn[n - 2]) > ((rhat * DIGIT_BASE) + un[j + n - 2])) {
                            qhat = qhat - 1;
                            rhat = rhat + vn[n - 1];
                            if (rhat < DIGIT_BASE) {
                                continue;
                            }
                        }

                        break;
                    }

                    carry = 0;
                    for (i = 0; i < n; i++) {
                        p = qhat * vn[i];
                        t = un[i + j] - carry - (p & DIGIT_MASK);
                        un[i + j] = t & DIGIT_MASK;
                        carry = Math.floor(p / DIGIT_BASE) - Math.floor(t / DIGIT_BASE);
                    }

                    t = un[j + n] - carry;
                    un[j + n] = t & DIGIT_MASK;

                    quotient[j] = qhat & DIGIT_MASK;

                    if (t < 0) {
                        quotient[j] = quotient[j] - 1;

                        carry = 0;
                        for (i = 0; i < n; i++) {
                            t = un[i + j] + vn[i] + carry;
                            un[i + j] = t & DIGIT_MASK;
                            carry = t >> DIGIT_BITS;
                        }
                        un[j + n] = (un[j + n] + carry) & DIGIT_MASK;
                    }
                }

                for (i = 0; i < n; i++) {
                    remainder[i] = ((un[i] >>> s) | (un[i + 1] << (DIGIT_BITS - s))) & DIGIT_MASK;
                }

                normalizeDigitArray(quotient);
                normalizeDigitArray(remainder);
            }

            function reduce(number, modulus, remainder, temp1, temp2) {
                var quotient = [];
                divRem(number, modulus, quotient, remainder, temp1, temp2);

                return remainder;
            }

            function modMul(multiplicand, multiplier, modulus, product, temp1, temp2) {
                var quotient = [];
                multiply(multiplicand, multiplier, quotient);
                divRem(quotient, modulus, quotient, product, temp1, temp2);

                return product;
            }

            function eea(a, b, upp, vpp, rpp) {
                var rp;
                if (isZero(a)) {
                    copyArray(b, 0, rpp, 0, b.length);
                    rpp.length = b.length;
                    return 0;
                } else if (isZero(b)) {
                    copyArray(a, 0, rpp, 0, a.length);
                    rpp.length = a.length;
                    return 0;
                } else if (compareDigits(a, b) < 0) {
                    rp = a.slice(0);
                    copyArray(b, 0, rpp, 0, b.length);
                    rpp.length = b.length;
                } else {
                    rp = b.slice(0);
                    copyArray(a, 0, rpp, 0, a.length);
                    rpp.length = a.length;
                }

                normalizeDigitArray(rpp);
                normalizeDigitArray(rp);
                var q = new Array(rpp.length);
                var r = new Array(rpp.length);

                var v = new Array(rpp.length);
                var vppPresent = vpp !== undefined;
                var vp;
                if (vppPresent) {
                    vp = new Array(rpp.length);
                    vp[0] = 1;
                    vp.length = 1;
                    vpp[0] = 0;
                    vpp.length = 1;
                }

                var up;
                var u = new Array(rpp.length);
                var uppPresent = upp !== undefined;
                if (uppPresent) {
                    up = new Array(rpp.length);
                    up[0] = 0;
                    up.length = 1;
                    upp[0] = 1;
                    upp.length = 1;
                }

                var k = -1;

                var upp_out = upp;
                var vpp_out = vpp;
                var rpp_out = rpp;
                var save;

                while (!isZero(rp)) {
                    divRem(rpp, rp, q, r, u, v);

                    if (uppPresent) {
                        multiply(q, up, u);
                        add(u, upp, u);
                        normalizeDigitArray(u);
                        save = upp;
                        upp = up;
                        up = u;
                        u = save;
                    }

                    if (vppPresent) {
                        multiply(q, vp, v);
                        add(v, vpp, v);
                        normalizeDigitArray(v);
                        save = vpp;
                        vpp = vp;
                        vp = v;
                        v = save;
                    }

                    save = rpp;
                    rpp = rp;
                    rp = r;
                    r = save;

                    k++;
                }

                if (uppPresent) {
                    copyArray(upp, 0, upp_out, 0, upp.length);
                    upp_out.length = upp.length;
                }
                if (vppPresent) {
                    copyArray(vpp, 0, vpp_out, 0, vpp.length);
                    vpp_out.length = vpp.length;
                }
                copyArray(rpp, 0, rpp_out, 0, rpp.length);
                rpp_out.length = rpp.length;

                return k;
            }

            function gcd(a, b, output) {
                var aa = a;
                var bb = b;
                if (compareDigits(a, b) > 0) {
                    aa = b;
                    bb = a;
                }

                eea(aa, bb, undefined, undefined, output);
                return normalizeDigitArray(output);
            }

            function modInv(a, n, aInv, pad) {
                var upp = new Array(n.length);
                var vpp = new Array(n.length);
                var rpp = new Array(n.length);
                var k = eea(a, n, vpp, upp, rpp);

                aInv = aInv || [];
                if (compareDigits(rpp, One) !== 0) {
                    aInv[0] = NaN;
                    aInv.length = 1;
                } else {
                    if ((k & 1) === 1) {
                        subtract(n, upp, aInv);
                    } else {
                        copyArray(upp, 0, aInv, 0, upp.length);
                        aInv.length = upp.length;
                    }
                    if (pad) {
                        normalizeDigitArray(aInv, n.length, true);
                    } else {
                        normalizeDigitArray(aInv);
                    }
                }

                return aInv;
            }

            function modInvCT(a, n, aInv, pad) {
                var nMinus2 = [];
                aInv = aInv || [];
                subtract(n, [2], nMinus2);
                modExp(a, nMinus2, n, aInv);
                normalizeDigitArray(aInv);
                return aInv;
            }

            function modExp(base, exponent, modulus, result) {
                result = result || [];

                if (compareDigits(exponent, Zero) === 0) {
                    result[0] = 1;
                } else if (compareDigits(exponent, One) === 0) {
                    copyArray(base, 0, result, 0, base.length);
                    result.length = base.length;
                } else {
                    var montmul = new MontgomeryMultiplier(modulus);
                    normalizeDigitArray(base, montmul.s, true);
                    montmul.modExp(
                        base,
                        exponent,
                        result);
                    result.length = modulus.length;
                }

                return result;
            }

            function MontgomeryMultiplier(modulus, context) {
                function computeM0Prime(m0) {
                    var m0Pr = 1;
                    var a = 2;
                    var b = 3;
                    var c = b & m0;

                    for (var i = 2; i <= DIGIT_BITS; i += 1) {
                        if (a < c) {
                            m0Pr += a;
                        }

                        a = a << 1;
                        b = (b << 1) | 1;
                        c = m0 * m0Pr & b;
                    }

                    var result = (~m0Pr & DIGIT_MASK) + 1;
                    return result;
                }

                function montgomeryReduction(t, m, result) {

                    var m0 = m[0];
                    var mPrime = computeM0Prime(m0);
                    var n = m.length;
                    var A = t.slice(0);
                    var ui = [];
                    var uimbi = [];
                    var uim = [];
                    var bi = [1];

                    for (var i = 0; i < n; i++) {

                        ui = (A[i] * mPrime) % DIGIT_BASE;

                        multiply(m, [ui], uim);
                        multiply(uim, bi, uimbi);

                        add(A, uimbi, A);

                        bi.unshift(0);
                    }

                    A = A.slice(n);
                    for (i = 0; i < A.length; i++) {
                        result[i] = A[i];
                    }

                }

                function montgomeryMultiply(multiplicand, multiplier, result, ctx) {
                    ctx = ctx || this;

                    var m = ctx.m,
                        s = m.length,
                        mPrime = ctx.mPrime,
                        m0 = ctx.m0,
                        rightI, r0, q, i = 0,
                        j, jm1, t1, t2, carry, rounds = 0;

                    var temp = createArray(s + 2);

                    while (i < s) {

                        rounds = Math.min(s, rounds + 16);

                        for (; i < rounds;) {

                            rightI = ~~multiplier[i];

                            r0 = temp[0] + multiplicand[0] * rightI;

                            q = ((r0 & DIGIT_MASK) * mPrime) & DIGIT_MASK;

                            temp[1] += ((m0 * q + r0) * DIG_INV) | 0;

                            for (j = 1, jm1 = 0; j < s; jm1 = j, j += 1) {
                                temp[jm1] = temp[j] + m[j] * q + multiplicand[j] * rightI;
                            }
                            temp[jm1] = temp[j];
                            temp[j] = 0;

                            i++;
                        }

                        carry = 0;
                        for (j = 0; j < s; j++) {
                            t1 = temp[j] + carry;
                            t2 = t1 & DIGIT_MASK;
                            temp[j] = t2;
                            carry = (t1 - t2) * DIG_INV;
                        }
                        temp[j] = carry;
                    }

                    for (i = 0; i < s; i += 1) {
                        result[i] = temp[i];
                    }
                    result.length = s;

                    var needSubtract = +(cryptoMath.compareDigits(temp, m) > 0);
                    cryptoMath.subtract(result, m, ctx.temp2);

                    ctSetArray(needSubtract, result, ctx.temp2);

                    return;
                }

                function convertToMontgomeryForm(digits) {
                    if (digits.length < this.s) {
                        digits.length = this.s;
                        for (var i = 0; i < this.s; i++) {
                            digits[i] = isNaN(digits[i]) ? 0 : digits[i];
                        }
                    }

                    var result = createArray(digits.length);

                    this.montgomeryMultiply(digits, this.rSquaredModm, result);
                    for (i = 0; i < this.s; i += 1) {
                        digits[i] = result[i];
                    }
                }

                function convertToStandardForm(digits) {
                    this.montgomeryMultiply(digits, this.one, this.temp1);
                    for (var i = 0; i < this.s; i += 1) {
                        digits[i] = this.temp1[i];
                    }
                }

                function optimalWindowSize(length) {

                    var i = 2,
                        t1, t0, bits = length * DIGIT_BITS;

                    t0 = 4 + Math.ceil(bits / 2) * 3 + 1;
                    do {
                        i++;
                        t1 = t0;
                        t0 = Math.pow(2, i) + Math.ceil(bits / i) * (i + 1) + 1;
                    } while (t0 < t1);

                    return i - 1;
                }

                function modExp(base, exponent, result, skipSideChannel) {
                    skipSideChannel = !!skipSideChannel;

                    var windowBits = optimalWindowSize(exponent.length);

                    var i, j,
                        expBits = fixedWindowRecode2(exponent, windowBits).reverse(),
                        partialResult = this.rModM.slice(0),
                        baseTableLen = Math.pow(2, windowBits),
                        bt = baseTable;

                    bt.length = baseTableLen;
                    bt[0] = this.rModM;
                    for (i = 1; i < baseTableLen; i++) {
                        bt[i] = [];
                        multiply(bt[i - 1], base, bt[i]);
                        this.reduce(bt[i]);
                    }

                    var tableVal = [];
                    var exp;

                    for (i = 0; i < expBits.length; i++) {
                        for (j = 0; j < windowBits; j++) {
                            this.montgomeryMultiply(partialResult, partialResult, partialResult);
                        }

                        exp = expBits[i];

                        skipSideChannel ?
                            (tableVal = bt[exp]) :
                            getTableEntry(bt, exp, tableVal);

                        this.montgomeryMultiply(partialResult, tableVal, partialResult);
                    }

                    this.montgomeryMultiply(partialResult, this.one, result);

                    return result;
                }

                function getTableEntry(bt, exp, tableVal) {

                    var z, t, mask, tableEntry, k;
                    for (z = 0; z < bt[0].length; z++) {
                        tableVal[z] = 0;
                    }
                    for (t = 0; t < bt.length; t++) {
                        tableEntry = bt[t];
                        mask = -(exp === t);
                        for (k = 0; k < tableEntry.length; k++) {
                            tableVal[k] = tableVal[k] | (tableEntry[k] & mask);
                        }
                    }
                }

                function ctSetArray(condition, a, b) {
                    var bMask = -condition;
                    var aMask = ~bMask;

                    for (var i = 0; i < a.length; i++) {
                        a[i] = (a[i] & aMask) | (b[i] & bMask);
                    }
                }

                function reduce(x, result) {
                    var k = this.m.length,
                        q1, q2, q3,
                        r1, r2,
                        i,
                        needSubtract,
                        temp = [];

                    result = result || x;

                    q1 = x.slice(k - 1);
                    q2 = [];
                    multiply(q1, this.mu, q2);
                    q3 = q2.slice(k + 1);

                    r1 = x.slice(0, k + 1);
                    r2 = [];
                    multiply(q3, m, r2);
                    r2 = r2.slice(0, k + 1);

                    r1[k + 1] = compareDigits(r1, r2) >>> 31;

                    for (i = 0; i < result.length; i++) {
                        result[i] = 0;
                    }
                    subtract(r1, r2, result);

                    needSubtract = +(compareDigits(result, m) > 0);
                    cryptoMath.subtract(result, m, temp);
                    ctSetArray(needSubtract, result, temp);

                    normalizeDigitArray(result);

                    return;
                }

                function computeContext(modulus) {

                    var s = modulus.length;

                    var m0 = modulus[0];

                    var ctx = {
                        m: modulus,
                        mPrime: computeM0Prime(m0),
                        m0: m0,
                        temp1: createArray(2 * s + 1),
                        temp2: createArray(2 * s + 1)
                    };

                    var R = createArray(modulus.length * 2);
                    R[R.length] = 1;
                    ctx.mu = [];
                    divRem(R, modulus, ctx.mu, []);

                    var quotient = createArray(2 * s + 1);
                    var rRemainder = createArray(s + 1);
                    var temp1 = createArray(2 * s + 1);
                    var temp2 = createArray(2 * s + 1);
                    var rDigits = rRemainder;
                    rDigits[s] = 1;
                    divRem(rDigits, modulus, quotient, rRemainder, temp1, temp2);
                    ctx.rModM = normalizeDigitArray(rRemainder, s, true);

                    var rSquaredModm = createArray(2 * s + 1);
                    var rSquaredDigits = rSquaredModm;
                    rSquaredDigits[s * 2] = 1;
                    divRem(rSquaredDigits, modulus, quotient, rSquaredModm, temp1, temp2);
                    ctx.rSquaredModm = normalizeDigitArray(rSquaredModm, s, true);

                    ctx.rCubedModm = createArray(s);
                    montgomeryMultiply(rSquaredModm, rSquaredModm, ctx.rCubedModm, ctx);

                    return ctx;
                }

                context = context || computeContext(modulus);

                var m = context.m;

                var mu = context.mu;

                var m0 = context.m0;

                var s = m.length;

                var zeros = createArray(s + 1);

                var one = zeros.slice(0, s);
                one[0] = 1;

                var mPrime = context.mPrime;

                var rModM = context.rModM;

                var rSquaredModm = context.rSquaredModm;

                var rCubedModm = context.rCubedModm;

                var temp1 = createArray(2 * s + 1);
                var temp2 = createArray(2 * s + 1);

                var baseTable = new Array(4);
                baseTable[0] = rModM;
                baseTable[1] = new Array(s);
                baseTable[2] = new Array(s);
                baseTable[3] = new Array(s);

                return {
                    m: m,

                    m0: m0,

                    mPrime: mPrime,
                    mu: mu,

                    rSquaredModm: rSquaredModm,
                    s: s,
                    rModM: rModM,
                    rCubedModm: rCubedModm,
                    one: one,
                    temp1: temp1,
                    temp2: temp2,

                    convertToMontgomeryForm: convertToMontgomeryForm,
                    convertToStandardForm: convertToStandardForm,
                    montgomeryMultiply: montgomeryMultiply,
                    modExp: modExp,
                    reduce: reduce,

                    ctx: context
                };
            }

            function IntegerGroup(modulusBytes) {
                var m_modulus = bytesToDigits(modulusBytes);

                var m_digitWidth = m_modulus.length;

                var m_zero = intToDigits(0, m_digitWidth);
                var m_one = intToDigits(1, m_digitWidth);

                var temp0 = createArray(m_digitWidth);
                var temp1 = createArray(m_digitWidth);

                var montmul = new MontgomeryMultiplier(m_modulus);

                function createElementFromBytes(bytes) {
                    var digits = bytesToDigits(bytes);

                    if (cryptoMath.compareDigits(digits, this.m_modulus) >= 0) {
                        throw new Error("The number provided is not an element of this group");
                    }

                    normalizeDigitArray(digits, this.m_digitWidth, true);
                    return integerGroupElement(digits, this);
                }

                function createElementFromInteger(integer) {
                    var digits = intToDigits(integer, this.m_digitWidth);
                    return integerGroupElement(digits, this);
                }

                function createElementFromDigits(digits) {
                    cryptoMath.normalizeDigitArray(digits, this.m_digitWidth, true);
                    return integerGroupElement(digits, this);
                }

                function equals(otherGroup) {
                    return compareDigits(this.m_modulus, otherGroup.m_modulus) === 0;
                }

                function add(addend1, addend2, sum) {
                    var i;
                    var s = this.m_digitWidth;
                    var result = sum.m_digits;
                    cryptoMath.add(addend1.m_digits, addend2.m_digits, result);
                    var mask = (compareDigits(result, this.m_modulus) >>> 31) - 1 & DIGIT_MASK;

                    var carry = 0;
                    for (i = 0; i < s; i += 1) {
                        carry = result[i] - (this.m_modulus[i] & mask) + carry;
                        result[i] = carry & DIGIT_MASK;
                        carry = (carry >> DIGIT_BITS);
                    }

                    result.length = s;
                }

                function subtract(leftElement, rightElement, outputElement) {
                    var i, s = this.m_digitWidth;
                    var result = outputElement.m_digits;
                    var carry = cryptoMath.subtract(leftElement.m_digits, rightElement.m_digits, outputElement.m_digits);

                    if (carry === -1) {
                        carry = 0;
                        for (i = 0; i < s; i += 1) {
                            carry += result[i] + this.m_modulus[i];
                            result[i] = carry & DIGIT_MASK;
                            carry = carry >> DIGIT_BITS;
                        }
                    }
                }

                function inverse(element, outputElement) {
                    cryptoMath.modInv(element.m_digits, this.m_modulus, outputElement.m_digits);
                }

                function multiply(multiplicand, multiplier, product) {
                    return cryptoMath.modMul(multiplicand.m_digits, multiplier.m_digits, this.m_modulus,
                        product.m_digits, temp0, temp1);
                }

                function modexp(valueElement, exponent, outputElement) {
                    outputElement = outputElement || integerGroupElement([], this);

                    if (compareDigits(exponent, m_zero) === 0) {
                        outputElement.m_digits = intToDigits(1, this.m_digitWidth);
                    } else if (compareDigits(exponent, m_one) === 0) {
                        for (var i = 0; i < valueElement.m_digits.length; i++) {
                            outputElement.m_digits[i] = valueElement.m_digits[i];
                        }
                        outputElement.m_digits.length = valueElement.m_digits.length;
                    } else {
                        this.montmul.modExp(
                            valueElement.m_digits,
                            exponent,
                            outputElement.m_digits);
                        outputElement.m_digits.length = this.montmul.s;
                    }

                    return outputElement;
                }

                function integerGroupElement(digits, group) {
                    return {
                        m_digits: digits,
                        m_group: group,

                        equals: function(element) {
                            return (compareDigits(this.m_digits, element.m_digits) === 0) &&
                                this.m_group.equals(this.m_group, element.m_group);
                        }
                    };
                }

                return {
                    m_modulus: m_modulus,
                    m_digitWidth: m_digitWidth,
                    montmul: montmul,

                    createElementFromInteger: createElementFromInteger,
                    createElementFromBytes: createElementFromBytes,
                    createElementFromDigits: createElementFromDigits,
                    equals: equals,
                    add: add,
                    subtract: subtract,
                    multiply: multiply,
                    inverse: inverse,
                    modexp: modexp
                };
            }

            return {
                DIGIT_BITS: DIGIT_BITS,
                DIGIT_NUM_BYTES: DIGIT_NUM_BYTES,
                DIGIT_MASK: DIGIT_MASK,
                DIGIT_BASE: DIGIT_BASE,
                DIGIT_MAX: DIGIT_MAX,
                Zero: Zero,
                One: One,

                normalizeDigitArray: normalizeDigitArray,
                bytesToDigits: bytesToDigits,
                stringToDigits: stringToDigits,
                digitsToString: digitsToString,
                intToDigits: intToDigits,
                digitsToBytes: digitsToBytes,
                isZero: isZero,
                isEven: isEven,

                shiftRight: shiftRight,
                shiftLeft: shiftLeft,
                compareDigits: compareDigits,
                bitLength: highestSetBit,

                fixedWindowRecode: fixedWindowRecode,
                IntegerGroup: IntegerGroup,

                add: add,
                subtract: subtract,
                multiply: multiply,
                divRem: divRem,
                reduce: reduce,
                modInv: modInv,
                modInvCT: modInvCT,
                modExp: modExp,
                modMul: modMul,
                MontgomeryMultiplier: MontgomeryMultiplier,
                gcd: gcd,
                sequenceEqual: sequenceEqual,
                swapEndianness: function(bytes) {
                    return bytes.reverse();
                },
                computeBitArray: computeBitArray
            };
        }

        var cryptoMath = cryptoMath || msrcryptoMath();

        var msrcryptoSha = function(name, der, h, k, blockBytes, blockFunction, truncateTo) {
            var utils = msrcryptoUtilities;

            var hv = h.slice(),
                w = new Array(blockBytes),
                buffer = [],
                blocksProcessed = 0;

            function hashBlocks(message) {
                var blockCount = Math.floor(message.length / blockBytes);

                for (var block = 0; block < blockCount; block++) {
                    blockFunction(message, block, hv, k, w);
                }

                blocksProcessed += blockCount;

                return message.slice(blockCount * blockBytes);
            }

            function hashToBytes() {
                var hash = [];

                for (var i = 0; i < hv.length; i++) {
                    hash = hash.concat(utils.int32ToBytes(hv[i]));
                }

                hash.length = truncateTo / 8;

                return hash;
            }

            function addPadding(messageBytes) {
                var padLen = blockBytes - messageBytes.length % blockBytes;

                (padLen <= (blockBytes / 8)) && (padLen += blockBytes);

                var padding = utils.getVector(padLen);

                padding[0] = 128;

                var messageLenBits = (messageBytes.length + blocksProcessed * blockBytes) * 8;

                for (var i = 1; i <= 8; i++) {
                    padding[padLen - i] = messageLenBits % 0x100;
                    messageLenBits = Math.floor(messageLenBits / 0x100);
                }
                return messageBytes.concat(padding);
            }

            function computeHash(messageBytes) {
                buffer = hashBlocks(messageBytes);

                return finish();
            }

            function process(messageBytes) {
                buffer = buffer.concat(messageBytes);

                if (buffer.length >= blockBytes) {

                    buffer = hashBlocks(buffer);
                }

                return;
            }

            function finish() {
                if (hashBlocks(addPadding(buffer)).length !== 0) {
                    throw new Error("buffer.length !== 0");
                }

                var result = hashToBytes();

                buffer = [];

                hv = h.slice();

                blocksProcessed = 0;

                return result;
            }

            return {
                name: name,
                computeHash: computeHash,
                process: process,
                finish: finish,
                der: der,
                hashLen: truncateTo,
                maxMessageSize: 0xFFFFFFFF
            };

        };

        var msrcryptoSha256 = (function() {

            var utils = msrcryptoUtilities;

            function hashBlock(message, blockIndex, hv, k, w) {
                var t, i, temp, x0, x1, blockSize = 64,
                    mask = 0xFFFFFFFF;

                var ra = hv[0],
                    rb = hv[1],
                    rc = hv[2],
                    rd = hv[3],
                    re = hv[4],
                    rf = hv[5],
                    rg = hv[6],
                    rh = hv[7];

                for (i = 0; i < 16; i++) {
                    w[i] = utils.bytesToInt32(message, blockIndex * blockSize + i * 4);
                }

                for (t = 16; t < 64; t++) {

                    x0 = w[t - 15];
                    x1 = w[t - 2];

                    w[t] = (((x1 >>> 17) | (x1 << 15)) ^ ((x1 >>> 19) | (x1 << 13)) ^ (x1 >>> 10)) +
                        w[t - 7] +
                        (((x0 >>> 7) | (x0 << 25)) ^ ((x0 >>> 18) | (x0 << 14)) ^ (x0 >>> 3)) +
                        w[t - 16];

                    w[t] = w[t] & mask;
                }

                for (i = 0; i < 64; i++) {

                    temp = rh +
                        ((re >>> 6 | re << 26) ^ (re >>> 11 | re << 21) ^ (re >>> 25 | re << 7)) +
                        ((re & rf) ^ ((~re) & rg)) +
                        k[i] + w[i];

                    rd += temp;

                    temp += ((ra >>> 2 | ra << 30) ^ (ra >>> 13 | ra << 19) ^ (ra >>> 22 | ra << 10)) +
                        ((ra & (rb ^ rc)) ^ (rb & rc));

                    rh = rg;
                    rg = rf;
                    rf = re;
                    re = rd;
                    rd = rc;
                    rc = rb;
                    rb = ra;
                    ra = temp;

                }

                hv[0] = (hv[0] + ra) >>> 0;
                hv[1] = (hv[1] + rb) >>> 0;
                hv[2] = (hv[2] + rc) >>> 0;
                hv[3] = (hv[3] + rd) >>> 0;
                hv[4] = (hv[4] + re) >>> 0;
                hv[5] = (hv[5] + rf) >>> 0;
                hv[6] = (hv[6] + rg) >>> 0;
                hv[7] = (hv[7] + rh) >>> 0;

                return hv;
            }

            var k256, h224, h256, der224, der256, upd = utils.unpackData;

            h224 = upd("wQWe2DZ81QcwcN0X9w5ZOf/ACzFoWBURZPmPp776T6Q", 4, 1);

            h256 = upd("agnmZ7tnroU8bvNypU/1OlEOUn+bBWiMH4PZq1vgzRk", 4, 1);

            k256 = upd("QoovmHE3RJG1wPvP6bXbpTlWwltZ8RHxkj+CpKscXtXYB6qYEoNbASQxhb5VDH3Dcr5ddIDesf6b3AanwZvxdOSbacHvvkeGD8GdxiQMocwt6SxvSnSEqlywqdx2+YjamD5RUqgxxm2wAyfIv1l/x8bgC/PVp5FHBspjURQpKWcntwqFLhshOE0sbfxTOA0TZQpzVHZqCruBwskuknIshaK/6KGoGmZLwkuLcMdsUaPRkugZ1pkGJPQONYUQaqBwGaTBFh43bAgnSHdMNLC8tTkcDLNO2KpKW5zKT2gub/N0j4LueKVjb4TIeBSMxwIIkL7/+qRQbOu++aP3xnF48g", 4, 1);

            der224 = upd("MC0wDQYJYIZIAWUDBAIEBQAEHA");

            der256 = upd("MDEwDQYJYIZIAWUDBAIBBQAEIA");

            return {
                sha224: function() {
                    return msrcryptoSha("SHA-224", der224, h224, k256, 64, hashBlock, 224);
                },
                sha256: function() {
                    return msrcryptoSha("SHA-256", der256, h256, k256, 64, hashBlock, 256);
                }
            };
        })();

        if (typeof operations !== "undefined") {

            msrcryptoSha256.instance224 = msrcryptoSha256.instance224 || msrcryptoSha256.sha224();
            msrcryptoSha256.instance256 = msrcryptoSha256.instance256 || msrcryptoSha256.sha256();

            msrcryptoSha256.instances = {};

            msrcryptoSha256.getInstance224 = function(id) {
                return msrcryptoSha256.instances[id] || (msrcryptoSha256.instances[id] = msrcryptoSha256.sha224());
            };

            msrcryptoSha256.getInstance256 = function(id) {
                return msrcryptoSha256.instances[id] || (msrcryptoSha256.instances[id] = msrcryptoSha256.sha256());
            };

            msrcryptoSha256.deleteInstance = function(id) {
                msrcryptoSha256.instances[id] = null;
                delete msrcryptoSha256.instances[id];
            };

            msrcryptoSha256.hash256 = function(p) {

                if (p.operationSubType === "process") {
                    msrcryptoSha256.getInstance256(p.workerid).process(p.buffer);
                    return null;
                }

                if (p.operationSubType === "finish") {

                    var result = msrcryptoSha256.getInstance256(p.workerid).finish();
                    msrcryptoSha256.deleteInstance(p.workerid);
                    return result;
                }

                if (p.operationSubType === "abort") {
                    msrcryptoSha256.deleteInstance(p.workerid);
                    return;
                }

                return msrcryptoSha256.instance256.computeHash(p.buffer);

            };

            msrcryptoSha256.hash224 = function(p) {

                if (p.operationSubType === "process") {
                    msrcryptoSha256.getInstance224(p.workerid).process(p.buffer);
                    return;
                }

                if (p.operationSubType === "finish") {
                    var result = msrcryptoSha256.getInstance224(p.workerid).finish();
                }

                if (p.operationSubType === "abort") {
                    msrcryptoSha224.deleteInstance(p.workerid);
                    return;
                }

                return msrcryptoSha256.instance224.computeHash(p.buffer);

            };

            operations.register("digest", "SHA-224", msrcryptoSha256.hash224);
            operations.register("digest", "SHA-256", msrcryptoSha256.hash256);
        }

        msrcryptoHashFunctions["SHA-224"] = msrcryptoSha256.sha224;
        msrcryptoHashFunctions["SHA-256"] = msrcryptoSha256.sha256;

        var msrcryptoHmac = function(keyBytes, hashFunction) {

            var blockSize = {
                "384": 128,
                "512": 128
            } [hashFunction.name.replace(/SHA-/, "")] || 64;
            var ipad;
            var opad;
            var paddedKey = padKey();
            var keyXorOpad;
            var keyXorIpad;
            var k0IpadText;

            function xorArrays(array1, array2) {
                var newArray = new Array(array1);
                for (var j = 0; j < array1.length; j++) {
                    newArray[j] = array1[j] ^ array2[j];
                }
                return newArray;
            }

            function padZeros(bytes, paddedLength) {
                var paddedArray = bytes.slice();
                for (var j = bytes.length; j < paddedLength; j++) {
                    paddedArray.push(0);
                }
                return paddedArray;
            }

            function padKey() {

                if (keyBytes.length === blockSize) {
                    return keyBytes;
                }

                if (keyBytes.length > blockSize) {
                    return padZeros(hashFunction.computeHash(keyBytes), blockSize);
                }

                return padZeros(keyBytes, blockSize);

            }

            function processHmac(messageBytes) {

                if (!k0IpadText) {
                    k0IpadText = keyXorIpad.concat(messageBytes);
                    hashFunction.process(k0IpadText);
                } else {
                    hashFunction.process(messageBytes);
                }
                return;
            }

            function finishHmac() {

                var hashK0IpadText = hashFunction.finish();

                var k0IpadK0OpadText = keyXorOpad.concat(hashK0IpadText);

                return hashFunction.computeHash(k0IpadK0OpadText);
            }

            function clearState() {
                keyBytes = null;
                hashFunction = null;
                paddedKey = null;
            }

            ipad = new Array(blockSize);
            opad = new Array(blockSize);
            for (var i = 0; i < blockSize; i++) {
                ipad[i] = 0x36;
                opad[i] = 0x5c;
            }
            keyXorIpad = xorArrays(paddedKey, ipad);
            keyXorOpad = xorArrays(paddedKey, opad);
            return {

                computeHmac: function(dataBytes, key, hashAlgorithm) {
                    processHmac(dataBytes);
                    var result = finishHmac();
                    clearState();
                    return result;
                },

                process: function(dataBytes, key, hashAlgorithm) {
                    processHmac(dataBytes);
                    return null;
                },

                finish: function(key, hashAlgorithm) {
                    var result = finishHmac();
                    clearState();
                    return result;
                }

            };
        };

        if (typeof operations !== "undefined") {

            var hmacInstances = {};

            msrcryptoHmac.signHmac = function(p) {

                var hashName = p.keyHandle.algorithm.hash.name.toUpperCase(),
                    hashAlg = msrcryptoHashFunctions[hashName](),
                    result,
                    id = p.workerid;

                if (!hmacInstances[id]) {
                    hmacInstances[id] = msrcryptoHmac(p.keyData, hashAlg);
                }

                if (p.operationSubType === "process") {
                    hmacInstances[id].process(p.buffer);
                    return null;
                }

                if (p.operationSubType === "finish") {
                    result = hmacInstances[id].finish();
                    hmacInstances[id] = null;
                    return result;
                }

                result = hmacInstances[id].computeHmac(p.buffer);
                hmacInstances[id] = null;
                return result;
            };

            msrcryptoHmac.verifyHmac = function(p) {

                var hashName = p.keyHandle.algorithm.hash.name.toUpperCase(),
                    hashAlg = msrcryptoHashFunctions[hashName](),
                    result,
                    id = p.workerid;

                if (!hmacInstances[id]) {
                    hmacInstances[id] = msrcryptoHmac(p.keyData, hashAlg);
                }

                if (p.operationSubType === "process") {
                    hmacInstances[id].process(p.buffer);
                    return null;
                }

                if (p.operationSubType === "finish") {
                    result = hmacInstances[id].finish();
                    result = msrcryptoUtilities.arraysEqual(result, p.signature);
                    hmacInstances[id] = null;
                    return result;
                }

                result = hmacInstances[id].computeHmac(p.buffer);
                result = msrcryptoUtilities.arraysEqual(result, p.signature);
                hmacInstances[id] = null;
                return result;
            };

            msrcryptoHmac.generateKey = function(p) {

                var defaultKeyLengths = {
                    "SHA-1": 64,
                    "SHA-224": 64,
                    "SHA-256": 64,
                    "SHA-384": 128,
                    "SHA-512": 128
                };

                var keyLength = p.algorithm.length;

                if (!keyLength) {
                    keyLength = defaultKeyLengths[p.algorithm.hash.name.toUpperCase()];
                }

                return {
                    type: "keyGeneration",
                    keyData: msrcryptoPseudoRandom.getBytes(keyLength),
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: null || p.usages,
                        type: "secret"
                    }
                };
            };

            msrcryptoHmac.importKey = function(p) {
                var keyObject,
                    keyBits = p.keyData.length * 8;

                if (p.format === "jwk") {
                    keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);
                    keyObject.alg = keyObject.alg.replace("HS", "SHA-");
                } else if (p.format === "raw") {
                    keyObject = {
                        k: msrcryptoUtilities.toArray(p.keyData)
                    };
                } else {
                    throw new Error("unsupported import format");
                }

                return {
                    type: "keyImport",
                    keyData: keyObject.k,
                    keyHandle: {
                        algorithm: {
                            name: "HMAC",
                            hash: {
                                name: p.algorithm.hash.name
                            }
                        },
                        extractable: p.extractable || keyObject.extractable,
                        usages: p.usages,
                        type: "secret"
                    }
                };

            };

            msrcryptoHmac.exportKey = function(p) {

                if (p.format === "jwk") {
                    return {
                        type: "keyExport",
                        keyHandle: msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData)
                    };
                }

                if (p.format === "raw") {
                    return {
                        type: "keyExport",
                        keyHandle: p.keyData
                    };
                }

                throw new Error("unsupported export format");
            };

            operations.register("importKey", "HMAC", msrcryptoHmac.importKey);
            operations.register("exportKey", "HMAC", msrcryptoHmac.exportKey);
            operations.register("generateKey", "HMAC", msrcryptoHmac.generateKey);
            operations.register("sign", "HMAC", msrcryptoHmac.signHmac);
            operations.register("verify", "HMAC", msrcryptoHmac.verifyHmac);
        }

        var msrcryptoBlockCipher = (function() {

            var aesConstants,
                x2,
                x3,
                x14,
                x13,
                x11,
                x9,
                sBoxTable,
                invSBoxTable,
                rConTable;

            return {

                aes: function(keyBytes) {

                    if (!aesConstants) {
                        aesConstants = msrcryptoUtilities.unpackData("AAIEBggKDA4QEhQWGBocHiAiJCYoKiwuMDI0Njg6PD5AQkRGSEpMTlBSVFZYWlxeYGJkZmhqbG5wcnR2eHp8foCChIaIioyOkJKUlpianJ6goqSmqKqsrrCytLa4ury+wMLExsjKzM7Q0tTW2Nrc3uDi5Obo6uzu8PL09vj6/P4bGR8dExEXFQsJDw0DAQcFOzk/PTMxNzUrKS8tIyEnJVtZX11TUVdVS0lPTUNBR0V7eX99c3F3dWtpb21jYWdlm5mfnZORl5WLiY+Ng4GHhbu5v72zsbe1q6mvraOhp6Xb2d/d09HX1cvJz83DwcfF+/n//fPx9/Xr6e/t4+Hn5QADBgUMDwoJGBseHRQXEhEwMzY1PD86OSgrLi0kJyIhYGNmZWxvaml4e359dHdycVBTVlVcX1pZSEtOTURHQkHAw8bFzM/Kydjb3t3U19LR8PP29fz/+vno6+7t5Ofi4aCjpqWsr6qpuLu+vbS3srGQk5aVnJ+amYiLjo2Eh4KBm5idnpeUkZKDgIWGj4yJiquora6npKGis7C1tr+8ubr7+P3+9/Tx8uPg5ebv7Onqy8jNzsfEwcLT0NXW39zZ2ltYXV5XVFFSQ0BFRk9MSUpraG1uZ2RhYnNwdXZ/fHl6Ozg9Pjc0MTIjICUmLywpKgsIDQ4HBAECExAVFh8cGRoADhwSODYkKnB+bGJIRlRa4O788tjWxMqQnoyCqKa0utvVx8nj7f/xq6W3uZOdj4E7NScpAw0fEUtFV1lzfW9hraOxv5WbiYfd08HP5ev5901DUV91e2lnPTMhLwULGRd2eGpkTkBSXAYIGhQ+MCIslpiKhK6gsrzm6Pr03tDCzEFPXVN5d2VrMT8tIwkHFRuhr72zmZeFi9HfzcPp5/X7mpSGiKKsvrDq5Pb40tzOwHp0ZmhCTF5QCgQWGDI8LiDs4vD+1NrIxpySgI6kqri2DAIQHjQ6KCZ8cmBuREpYVjc5KyUPARMdR0lbVX9xY23X2cvF7+Hz/aepu7WfkYONAA0aFzQ5LiNoZXJ/XFFGS9Ddysfk6f7zuLWir4yBlpu7tqGsj4KVmNPeycTn6v3wa2ZxfF9SRUgDDhkUNzotIG1gd3pZVENOBQgfEjE8Kya9sKeqiYSTntXYz8Lh7Pv21tvMweLv+PW+s6SpioeQnQYLHBEyPyglbmN0eVpXQE3a18DN7uP0+bK/qKWGi5yRCgcQHT4zJClib3h1VltMQWFse3ZVWE9CCQQTHj0wJyqxvKumhYifktnUw87t4Pf6t7qtoIOOmZTf0sXI6+bx/GdqfXBTXklEDwIVGDs2ISwMARYbODUiL2RpfnNQXUpH3NHGy+jl8v+0ua6jgI2alwALFh0sJzoxWFNORXR/Ymmwu6atnJeKgejj/vXEz9LZe3BtZldcQUojKDU+DwQZEsvA3dbn7PH6k5iFjr+0qaL2/eDr2tHMx66luLOCiZSfRk1QW2phfHceFQgDMjkkL42Gm5Chqre81d7DyPny7+Q9NisgERoHDGVuc3hJQl9U9/zh6tvQzcavpLmyg4iVnkdMUVprYH12HxQJAjM4JS6Mh5qRoKu2vdTfwsn48+7lPDcqIRAbBg1kb3J5SENeVQEKFxwtJjswWVJPRHV+Y2ixuqesnZaLgOni//TFztPYenFsZ1ZdQEsiKTQ/DgUYE8rB3Nfm7fD7kpmEj761qKMACRIbJC02P0hBWlNsZX53kJmCi7S9pq/Y0crD/PXu5zsyKSAfFg0Ec3phaFdeRUyrormwj4adlOPq8fjHztXcdn9kbVJbQEk+NywlGhMIAebv9P3Cy9DZrqe8tYqDmJFNRF9WaWB7cgUMFx4hKDM63dTPxvnw6+KVnIeOsbijquzl/vfIwdrTpK22v4CJkpt8dW5nWFFKQzQ9Ji8QGQIL197FzPP64eiflo2Eu7KpoEdOVVxjanF4DwYdFCsiOTCak4iBvrespdLbwMn2/+TtCgMYES4nPDVCS1BZZm90faGos7qFjJee6eD78s3E39YxOCMqFRwHDnlwa2JdVE9GY3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7FlIJatUwNqU4v0CjnoHz1/t84zmCmy//hzSOQ0TE3unLVHuUMqbCIz3uTJULQvrDTgguoWYo2SSydluiSW2L0SVy+PZkhmiYFtSkXMxdZbaSbHBIUP3tudpeFUZXp42dhJDYqwCMvNMK9+RYBbizRQbQLB6Pyj8PAsGvvQMBE4prOpERQU9n3OqX8s/O8LTmc5asdCLnrTWF4vk36Bx1325H8RpxHSnFiW+3Yg6qGL4b/FY+S8bSeSCa28D+eM1a9B/dqDOIB8cxsRIQWSeA7F9gUX+pGbVKDS3lep+TyZzvoOA7Ta4q9bDI67s8g1OZYRcrBH66d9Ym4WkUY1UhDH2NAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuNAQIECBAgQIAbNmzYq02aL168Y8aXNWrUs33678WROXLk071hwp8lSpQzZsyDHTp06MuN", 256, false);
                        x2 = aesConstants[0];
                        x3 = aesConstants[1];
                        x14 = aesConstants[2];
                        x13 = aesConstants[3];
                        x11 = aesConstants[4];
                        x9 = aesConstants[5];
                        sBoxTable = aesConstants[6];
                        invSBoxTable = aesConstants[7];
                        rConTable = aesConstants[8];
                    }

                    var blockSize = 128,
                        keyLength,
                        nK,
                        nB = 4,
                        nR,
                        key;

                    keyLength = keyBytes.length * 8;

                    switch (keyLength) {
                        case 128:
                        case 192:
                        case 256:
                            break;
                        default:
                            throw new Error("Unsupported keyLength");
                    }

                    nK = keyLength / 32;
                    nR = nK + 6;

                    var shiftRows = function(a) {
                        var tmp = a[1];
                        a[1] = a[5];
                        a[5] = a[9];
                        a[9] = a[13];
                        a[13] = tmp;
                        tmp = a[2];
                        a[2] = a[10];
                        a[10] = tmp;
                        tmp = a[6];
                        a[6] = a[14];
                        a[14] = tmp;
                        tmp = a[15];
                        a[15] = a[11];
                        a[11] = a[7];
                        a[7] = a[3];
                        a[3] = tmp;
                    };

                    var invShiftRows = function(a) {
                        var tmp = a[13];
                        a[13] = a[9];
                        a[9] = a[5];
                        a[5] = a[1];
                        a[1] = tmp;
                        tmp = a[10];
                        a[10] = a[2];
                        a[2] = tmp;
                        tmp = a[14];
                        a[14] = a[6];
                        a[6] = tmp;
                        tmp = a[3];
                        a[3] = a[7];
                        a[7] = a[11];
                        a[11] = a[15];
                        a[15] = tmp;
                    };

                    var mixColumns = function(state) {
                        var a = state[0],
                            b = state[1],
                            c = state[2],
                            d = state[3],
                            e = state[4],
                            f = state[5],
                            g = state[6],
                            h = state[7],
                            i = state[8],
                            j = state[9],
                            k = state[10],
                            l = state[11],
                            m = state[12],
                            n = state[13],
                            o = state[14],
                            p = state[15];

                        state[0] = x2[a] ^ x3[b] ^ c ^ d;
                        state[1] = a ^ x2[b] ^ x3[c] ^ d;
                        state[2] = a ^ b ^ x2[c] ^ x3[d];
                        state[3] = x3[a] ^ b ^ c ^ x2[d];
                        state[4] = x2[e] ^ x3[f] ^ g ^ h;
                        state[5] = e ^ x2[f] ^ x3[g] ^ h;
                        state[6] = e ^ f ^ x2[g] ^ x3[h];
                        state[7] = x3[e] ^ f ^ g ^ x2[h];
                        state[8] = x2[i] ^ x3[j] ^ k ^ l;
                        state[9] = i ^ x2[j] ^ x3[k] ^ l;
                        state[10] = i ^ j ^ x2[k] ^ x3[l];
                        state[11] = x3[i] ^ j ^ k ^ x2[l];
                        state[12] = x2[m] ^ x3[n] ^ o ^ p;
                        state[13] = m ^ x2[n] ^ x3[o] ^ p;
                        state[14] = m ^ n ^ x2[o] ^ x3[p];
                        state[15] = x3[m] ^ n ^ o ^ x2[p];
                    };

                    var invMixColumns = function(state) {
                        var a = state[0],
                            b = state[1],
                            c = state[2],
                            d = state[3],
                            e = state[4],
                            f = state[5],
                            g = state[6],
                            h = state[7],
                            i = state[8],
                            j = state[9],
                            k = state[10],
                            l = state[11],
                            m = state[12],
                            n = state[13],
                            o = state[14],
                            p = state[15];

                        state[0] = x14[a] ^ x11[b] ^ x13[c] ^ x9[d];
                        state[1] = x9[a] ^ x14[b] ^ x11[c] ^ x13[d];
                        state[2] = x13[a] ^ x9[b] ^ x14[c] ^ x11[d];
                        state[3] = x11[a] ^ x13[b] ^ x9[c] ^ x14[d];
                        state[4] = x14[e] ^ x11[f] ^ x13[g] ^ x9[h];
                        state[5] = x9[e] ^ x14[f] ^ x11[g] ^ x13[h];
                        state[6] = x13[e] ^ x9[f] ^ x14[g] ^ x11[h];
                        state[7] = x11[e] ^ x13[f] ^ x9[g] ^ x14[h];
                        state[8] = x14[i] ^ x11[j] ^ x13[k] ^ x9[l];
                        state[9] = x9[i] ^ x14[j] ^ x11[k] ^ x13[l];
                        state[10] = x13[i] ^ x9[j] ^ x14[k] ^ x11[l];
                        state[11] = x11[i] ^ x13[j] ^ x9[k] ^ x14[l];
                        state[12] = x14[m] ^ x11[n] ^ x13[o] ^ x9[p];
                        state[13] = x9[m] ^ x14[n] ^ x11[o] ^ x13[p];
                        state[14] = x13[m] ^ x9[n] ^ x14[o] ^ x11[p];
                        state[15] = x11[m] ^ x13[n] ^ x9[o] ^ x14[p];
                    };

                    var xorWord = function(a, b) {
                        return [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]];
                    };

                    var addRoundKey = function(state, keySchedule, offset) {
                        for (var i = 0; i < state.length; i += 1) {
                            state[i] ^= keySchedule[i + offset];
                        }
                    };

                    var rotWord = function(word) {
                        var a = word[0];
                        word[0] = word[1];
                        word[1] = word[2];
                        word[2] = word[3];
                        word[3] = a;
                    };

                    var subWord = function(word) {
                        for (var i = 0; i < word.length; i += 1) {
                            word[i] = sBoxTable[word[i]];
                        }
                    };

                    var invSubWord = function(word) {
                        for (var i = 0; i < word.length; i += 1) {
                            word[i] = invSBoxTable[word[i]];
                        }
                    };

                    var getWord = function(tab, i) {
                        return [tab[4 * i], tab[4 * i + 1], tab[4 * i + 2], tab[4 * i + 3]];
                    };

                    var setWord = function(left, right, indexL, indexR) {
                        left[4 * indexL] = right[4 * indexR];
                        left[4 * indexL + 1] = right[4 * indexR + 1];
                        left[4 * indexL + 2] = right[4 * indexR + 2];
                        left[4 * indexL + 3] = right[4 * indexR + 3];
                    };

                    var expandKey = function(keyIn) {
                        var temp, res = [],
                            i = 0;
                        while (i < 4 * nK) {
                            res.push(keyIn[i++]);
                        }

                        i = nK;
                        while (i < nB * (nR + 1)) {
                            temp = getWord(res, i - 1);
                            if (i % nK === 0) {
                                var index = i / nK;
                                var rcon = [rConTable[index], 0, 0, 0];
                                rotWord(temp);
                                subWord(temp);
                                temp = xorWord(temp, rcon);
                            } else if (nK > 6 && i % nK === 4) {
                                subWord(temp);
                            }
                            var newWord = xorWord(getWord(res, i - nK), temp);
                            setWord(res, newWord, i, 0);
                            i += 1;
                        }
                        return res;
                    };

                    key = expandKey(keyBytes);

                    return {

                        encrypt: function(dataBytes) {
                            var state = dataBytes,
                                round;

                            addRoundKey(state, key, 0);
                            for (round = 1; round <= nR - 1; round += 1) {
                                subWord(state);
                                shiftRows(state);
                                mixColumns(state);
                                addRoundKey(state, key, 4 * round * nB);
                            }
                            subWord(state);
                            shiftRows(state);
                            addRoundKey(state, key, 4 * nR * nB);

                            return state;
                        },

                        decrypt: function(dataBytes) {
                            var state = dataBytes,
                                round;

                            addRoundKey(state, key, 4 * nR * nB);
                            for (round = nR - 1; round >= 1; round -= 1) {
                                invShiftRows(state);
                                invSubWord(state);
                                addRoundKey(state, key, 4 * round * nB);
                                invMixColumns(state);
                            }
                            invShiftRows(state);
                            invSubWord(state);
                            addRoundKey(state, key, 0);

                            return state;
                        },

                        clear: function() {},

                        keyLength: keyLength,

                        blockSize: blockSize

                    };
                }

            };

        })();

        var msrcryptoPadding = msrcryptoPadding || {};

        msrcryptoPadding.pkcsv7 = function(blockSize) {

            function pad(messageBlocks) {
                var lastIndex = messageBlocks.length - 1 >= 0 ? messageBlocks.length - 1 : 0;
                var lastBlock = messageBlocks[lastIndex];
                var lastBlockLength = lastBlock.length;
                var createNewBlock = lastBlockLength === blockSize;

                if (createNewBlock) {
                    var newBlock = [];
                    var i;
                    for (i = 0; i < blockSize; i += 1) {
                        newBlock.push(blockSize);
                    }
                    messageBlocks.push(newBlock);
                } else {
                    var byteToAdd = blockSize - lastBlockLength & 0xff;
                    while (lastBlock.length !== blockSize) {
                        lastBlock.push(byteToAdd);
                    }
                }

            }

            function unpad(messageBytes) {
                var verified = true;

                if (messageBytes.length % blockSize !== 0) {
                    verified = false;
                }

                var lastBlock = messageBytes.slice(-blockSize);

                var padLen = lastBlock[lastBlock.length - 1];

                for (var i = 0; i < blockSize; i++) {
                    var isPaddingElement = blockSize - i <= padLen;
                    var isCorrectValue = lastBlock[i] === padLen;
                    verified = (isPaddingElement ? isCorrectValue : true) && verified;
                }

                var trimLen = verified ? padLen : 0;

                messageBytes.length -= trimLen;

                return verified;
            }

            return {
                pad: pad,
                unpad: unpad
            };

        };

        var msrcryptoCbc = function(blockCipher) {

            var blockSize = blockCipher.blockSize / 8;

            var paddingScheme = msrcryptoPadding.pkcsv7(blockSize);

            var mergeBlocks = function(tab) {
                var res = [],
                    i, j;
                for (i = 0; i < tab.length; i += 1) {
                    var block = tab[i];
                    for (j = 0; j < block.length; j += 1) {
                        res.push(block[j]);
                    }
                }
                return res;
            };

            function getBlocks(dataBytes) {

                var blocks = [];

                mBuffer = mBuffer.concat(dataBytes);

                var blockCount = Math.floor(mBuffer.length / blockSize);

                for (var i = 0; i < blockCount; i++) {
                    blocks.push(mBuffer.slice(i * blockSize, (i + 1) * blockSize));
                }

                mBuffer = mBuffer.slice(blockCount * blockSize);

                return blocks;
            }

            function encryptBlocks(blocks) {

                var result = [],
                    toEncrypt;

                for (var i = 0; i < blocks.length; i++) {
                    toEncrypt = msrcryptoUtilities.xorVectors(mIvBytes, blocks[i]);
                    result.push(blockCipher.encrypt(toEncrypt));
                    mIvBytes = result[i];
                }

                return result;
            }

            function decryptBlocks(blocks) {

                var result = [],
                    toDecrypt,
                    decrypted;

                for (var i = 0; i < blocks.length; i += 1) {
                    toDecrypt = blocks[i].slice(0, blocks[i].length);
                    decrypted = blockCipher.decrypt(toDecrypt);
                    result.push(msrcryptoUtilities.xorVectors(mIvBytes, decrypted));
                    mIvBytes = blocks[i];
                }

                return result;
            }

            function clearState() {
                mBuffer = [];
                mResultBuffer = [];
                mIvBytes = null;
            }

            var mBuffer = [],
                mResultBuffer = [],
                mIvBytes;

            return {

                init: function(ivBytes) {

                    if (ivBytes.length !== blockSize) {
                        throw new Error("Invalid iv size");
                    }

                    mIvBytes = ivBytes.slice();
                },

                encrypt: function(plainBytes) {
                    var result = encryptBlocks(getBlocks(plainBytes));
                    mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

                    return this.finishEncrypt();
                },

                processEncrypt: function(plainBytes) {

                    var result = mergeBlocks(encryptBlocks(getBlocks(plainBytes)));

                    return result;
                },

                finishEncrypt: function() {

                    var blocks = mBuffer.length === 1 ? [
                        [mBuffer[0]]
                    ] : [mBuffer];

                    paddingScheme.pad(blocks);

                    var result = mResultBuffer.concat(mergeBlocks(encryptBlocks(blocks)));

                    clearState();

                    return result;
                },

                decrypt: function(cipherBytes) {
                    this.processDecrypt(cipherBytes);

                    return this.finishDecrypt();
                },

                processDecrypt: function(cipherBytes) {

                    var result = decryptBlocks(getBlocks(cipherBytes));

                    mResultBuffer = mResultBuffer.concat(mergeBlocks(result));

                    return;
                },

                finishDecrypt: function() {

                    var result = mResultBuffer;

                    var verified = paddingScheme.unpad(result);

                    clearState();

                    return result;
                }

            };
        };

        if (typeof operations !== "undefined") {

            var cbcInstances = {};

            msrcryptoCbc.workerEncrypt = function(p) {

                var result,
                    id = p.workerid;

                if (!cbcInstances[id]) {
                    cbcInstances[id] = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
                    cbcInstances[id].init(p.algorithm.iv);
                }

                if (p.operationSubType === "process") {
                    return cbcInstances[id].processEncrypt(p.buffer);
                }

                if (p.operationSubType === "finish") {
                    result = cbcInstances[id].finishEncrypt();
                    cbcInstances[id] = null;
                    return result;
                }

                result = cbcInstances[id].encrypt(p.buffer);
                cbcInstances[id] = null;
                return result;
            };

            msrcryptoCbc.workerDecrypt = function(p) {

                var result,
                    id = p.workerid;

                if (!cbcInstances[id]) {
                    cbcInstances[id] = msrcryptoCbc(msrcryptoBlockCipher.aes(p.keyData));
                    cbcInstances[id].init(p.algorithm.iv);
                }

                if (p.operationSubType === "process") {
                    cbcInstances[id].processDecrypt(p.buffer);
                    return;
                }

                if (p.operationSubType === "finish") {
                    result = cbcInstances[id].finishDecrypt();
                    cbcInstances[id] = null;
                    return result;
                }

                result = cbcInstances[id].decrypt(p.buffer);
                cbcInstances[id] = null;
                return result;
            };

            msrcryptoCbc.generateKey = function(p) {

                if (p.algorithm.length % 8 !== 0) {
                    throw new Error();
                }

                return {
                    type: "keyGeneration",
                    keyData: msrcryptoPseudoRandom.getBytes(Math.floor(p.algorithm.length / 8)),
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: null || p.usages,
                        type: "secret"
                    }
                };
            };

            msrcryptoCbc.importKey = function(p) {

                var keyObject;
                var keyBits = p.keyData.length * 8;

                if (p.format === "jwk") {
                    keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["k"]);
                } else if (p.format === "raw") {
                    if (keyBits !== 128 && keyBits !== 192 && keyBits !== 256) {
                        throw new Error("invalid key length (should be 128, 192, or 256 bits)");
                    }
                    keyObject = {
                        k: msrcryptoUtilities.toArray(p.keyData)
                    };
                } else {
                    throw new Error("unsupported import format");
                }

                p.algorithm.length = keyObject.k.length * 8;

                return {
                    keyData: keyObject.k,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable || keyObject.extractable,
                        usages: null || p.usages,
                        type: "secret"
                    },
                    type: "keyImport"
                };
            };

            msrcryptoCbc.exportKey = function(p) {

                if (p.format === "jwk") {
                    return {
                        type: "keyExport",
                        keyHandle: msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData)
                    };
                }

                if (p.format === "raw") {
                    return {
                        type: "keyExport",
                        keyHandle: p.keyData
                    };
                }

                throw new Error("unsupported export format");
            };

            operations.register("importKey", "AES-CBC", msrcryptoCbc.importKey);
            operations.register("exportKey", "AES-CBC", msrcryptoCbc.exportKey);
            operations.register("generateKey", "AES-CBC", msrcryptoCbc.generateKey);
            operations.register("encrypt", "AES-CBC", msrcryptoCbc.workerEncrypt);
            operations.register("decrypt", "AES-CBC", msrcryptoCbc.workerDecrypt);
        }

        function MsrcryptoPrng() {
            if (!(this instanceof MsrcryptoPrng)) {
                throw new Error("create MsrcryptoPrng object with new keyword");
            }

            var initialized = false;

            var key;
            var v;
            var keyLen;
            var seedLen;
            var reseedCounter = 1;
            var reseedInterval = Math.pow(2, 48);

            initialize();

            function addOne(counter) {
                var i;
                for (i = counter.length - 1; i >= 0; i -= 1) {
                    counter[i] += 1;
                    if (counter[i] >= 256) {
                        counter[i] = 0;
                    }
                    if (counter[i]) {
                        break;
                    }
                }
            }

            function initialize() {
                key = msrcryptoUtilities.getVector(32);
                v = msrcryptoUtilities.getVector(16);
                keyLen = 32;
                seedLen = 48;
                reseedCounter = 1;
            }

            function reseed(entropy, additionalEntropy) {
                additionalEntropy = additionalEntropy || [0];
                if (additionalEntropy.length > seedLen) {
                    throw new Error("Incorrect entropy or additionalEntropy length");
                }
                additionalEntropy = additionalEntropy.concat(msrcryptoUtilities.getVector(seedLen - additionalEntropy.length));

                entropy = entropy.concat(msrcryptoUtilities.getVector((seedLen - (entropy.length % seedLen)) % seedLen));
                for (var i = 0; i < entropy.length; i += seedLen) {
                    var seedMaterial = msrcryptoUtilities.xorVectors(entropy.slice(i, i + seedLen), additionalEntropy);
                    update(seedMaterial);
                }
                reseedCounter = 1;
            }

            function update(providedData) {
                var temp = [];
                var blockCipher = new msrcryptoBlockCipher.aes(key);
                while (temp.length < seedLen) {
                    addOne(v);
                    var toEncrypt = v.slice(0, 16);
                    var outputBlock = blockCipher.encrypt(toEncrypt);
                    temp = temp.concat(outputBlock);
                }
                temp = msrcryptoUtilities.xorVectors(temp, providedData);
                key = temp.slice(0, keyLen);
                v = temp.slice(keyLen);
            }

            function generate(requestedBytes, additionalInput) {
                if (requestedBytes >= 65536) {
                    throw new Error("too much random requested");
                }
                if (reseedCounter > reseedInterval) {
                    throw new Error("Reseeding is required");
                }
                if (additionalInput && additionalInput.length > 0) {
                    while (additionalInput.length < seedLen) {
                        additionalInput = additionalInput.concat(
                            msrcryptoUtilities.getVector(seedLen - additionalInput.length));
                    }
                    update(additionalInput);
                } else {
                    additionalInput = msrcryptoUtilities.getVector(seedLen);
                }
                var temp = [];
                var blockCipher = new msrcryptoBlockCipher.aes(key);
                while (temp.length < requestedBytes) {
                    addOne(v);
                    var toEncrypt = v.slice(0, v.length);
                    var outputBlock = blockCipher.encrypt(toEncrypt);
                    temp = temp.concat(outputBlock);
                }
                temp = temp.slice(0, requestedBytes);
                update(additionalInput);
                reseedCounter += 1;
                return temp;
            }

            return {
                reseed: reseed,
                getBytes: function(length, additionalInput) {
                    if (!initialized) {
                        throw new Error("can't get randomness before initialization");
                    }
                    return generate(length, additionalInput);
                },
                getNonZeroBytes: function(length, additionalInput) {
                    if (!initialized) {
                        throw new Error("can't get randomness before initialization");
                    }
                    var result = [];
                    var buff;
                    while (result.length < length) {
                        buff = generate(length, additionalInput);
                        for (var i = 0; i < buff.length; i += 1) {
                            if (buff[i] !== 0) {
                                result.push(buff[i]);
                            }
                        }
                    }
                    return result.slice(0, length);
                },
                init: function(entropy, personalization) {
                    if (entropy.length < seedLen) {
                        throw new Error("Initial entropy length too short");
                    }
                    initialize();
                    reseed(entropy, personalization);
                    initialized = true;
                }
            };
        }

        var msrcryptoPseudoRandom = new MsrcryptoPrng();

        function MsrcryptoEntropy(global) {
            var poolLength = 48;
            var collectorPool = [];
            var collectorPoolLength = 128;
            var collectorsRegistered = 0;
            var entropyPoolPrng = new MsrcryptoPrng();
            var initialized = false;
            var cryptographicPRNGPresent = false;
            var globalScope = global;

            function collectEntropy() {

                var headerList = ["Cookie", "RedirectUri", "ETag", "x-ms-client-antiforgery-id", "x-ms-client-request-id",
                    "x-ms-client-session-id", "SubscriptionPool"
                ];

                var i, pool = [];

                for (i = 0; i < poolLength; i += 1) {
                    pool[i] = Math.floor(Math.random() * 256);
                }

                var prngCrypto = globalScope.crypto || globalScope.msCrypto;
                if (prngCrypto && typeof prngCrypto.getRandomValues === "function") {
                    if (global.Uint8Array) {
                        var res = new global.Uint8Array(poolLength);
                        prngCrypto.getRandomValues(res);
                        pool = pool.concat(Array.apply(null, res));
                        cryptographicPRNGPresent = true;
                    }
                }

                if (typeof XMLHttpRequest !== "undefined") {
                    var req = new XMLHttpRequest();
                    for (i = 0; i < headerList.length; i += 1) {
                        try {
                            var header = req.getResponseHeader(headerList[i]);
                            if (header) {
                                var arr = msrcryptoUtilities.stringToBytes(header);
                                pool = pool.concat(arr);
                            }
                        } catch (err) {}
                    }
                }
                if (!cryptographicPRNGPresent && canCollect) {
                    pool = pool.concat(collectorPool.splice(0, collectorPool.length));
                    collectors.startCollectors();
                }

                initialized ? entropyPoolPrng.reseed(pool) : entropyPoolPrng.init(pool);
                initialized = true;
            }

            function updatePool(entropyData) {
                for (var i = 0; i < entropyData.length; ++i) {
                    collectorPool.push(entropyData[i]);
                }
                if (collectorPool.length >= collectorPoolLength) {
                    collectors.stopCollectors();
                }
            }

            var canCollect = (global && global.addEventListener) ||
                (typeof document !== "undefined" && document.attachEvent);
            var collectors = (function() {
                return {
                    startCollectors: function() {
                        if (!this.collectorsRegistered) {
                            if (global.addEventListener) {
                                global.addEventListener("mousemove", this.MouseEventCallBack, true);
                                global.addEventListener("load", this.LoadTimeCallBack, true);
                            } else if (document.attachEvent) {
                                document.attachEvent("onmousemove", this.MouseEventCallBack);
                                document.attachEvent("onload", this.LoadTimeCallBack);
                            } else {
                                throw new Error("Can't attach events for entropy collection");
                            }

                            this.collectorsRegistered = 1;
                        }
                    },
                    stopCollectors: function() {
                        if (this.collectorsRegistered) {
                            if (global.removeEventListener) {
                                global.removeEventListener("mousemove", this.MouseEventCallBack, 1);
                                global.removeEventListener("load", this.LoadTimeCallBack, 1);
                            } else if (global.detachEvent) {
                                global.detachEvent("onmousemove", this.MouseEventCallBack);
                                global.detachEvent("onload", this.LoadTimeCallBack);
                            }

                            this.collectorsRegistered = 0;
                        }
                    },
                    MouseEventCallBack: function(eventData) {
                        var d = (new Date()).valueOf();
                        var x = eventData.x || eventData.clientX || eventData.offsetX || 0;
                        var y = eventData.y || eventData.clientY || eventData.offsetY || 0;
                        var arr = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff,
                            x & 0x0ff, (x >> 8) & 0x0ff, y & 0x0ff, (y >> 8) & 0x0ff
                        ];

                        updatePool(arr);
                    },
                    LoadTimeCallBack: function() {
                        var d = (new Date()).valueOf();
                        var dateArray = [d & 0x0ff, (d >> 8) & 0x0ff, (d >> 16) & 0x0ff, (d >> 24) & 0x0ff];

                        updatePool(dateArray);
                    }
                };
            })();

            return {
                init: function() {
                    collectEntropy();

                    if (!cryptographicPRNGPresent && !collectorsRegistered && canCollect) {
                        try {
                            collectors.startCollectors();
                        } catch (e) {}
                    }
                },

                reseed: function(entropy) {
                    entropyPoolPrng.reseed(entropy);
                },

                read: function(length) {
                    if (!initialized) {
                        throw new Error("Entropy pool is not initialized.");
                    }

                    var ret = entropyPoolPrng.getBytes(length);

                    collectEntropy();

                    return ret;
                }
            };
        }

        var prime = (function() {

            var smallPrimes = [];

            var trialValues = [];

            var MAX_SMALL_PRIMES = 4096 * 4;

            function primeSieve(max) {
                var numbers = new Array(max + 1),
                    results = [],
                    i, j,
                    limit = Math.sqrt(max) | 0;

                for (i = 3; i <= limit; i += 2) {
                    for (j = i * i; j <= max; j += i * 2) {
                        numbers[j] = 0;
                    }
                }

                for (i = 3; i <= max; i += 2) {
                    if (numbers[i] !== 0) {
                        results.push(i);
                    }
                }

                return results;
            }

            function incrementalTrialDivision(increment) {
                var i,
                    len = trialValues.length;

                for (i = 0; i < len; i++) {
                    if ((trialValues[i] + increment) % smallPrimes[i] === 0) {
                        return false;
                    }
                }

                return true;
            }

            function setupIncrementalTrialDivision(candidate) {

                var i, j, r, p, y,
                    primeCount,
                    len = candidate.length - 1,
                    db = cryptoMath.DIGIT_BASE,
                    h = candidate[len];

                if (smallPrimes.length === 0) {
                    smallPrimes = primeSieve(MAX_SMALL_PRIMES);
                }
                primeCount = smallPrimes.length;

                trialValues = new Array(primeCount);

                for (i = 0; i < primeCount; i++) {

                    j = len;
                    y = smallPrimes[i];

                    if (h < y) {
                        r = h;
                        j--;
                    } else {
                        r = 0;
                    }

                    while (j >= 0) {
                        p = r * db + candidate[j--];
                        r = p - (p / y | 0) * y;
                    }

                    trialValues[i] = r;
                }

                return;
            }

            function largestDivisibleByPowerOfTwo(number) {

                var k = 0,
                    i = 0,
                    s = 0,
                    j;
                if (cryptoMath.isZero(number)) {
                    return 0;
                }
                for (k = 0; number[k] === 0; k++) {}
                for (i = 0, j = 2; number[k] % j === 0; j *= 2, i++) {}
                return k * cryptoMath.DIGIT_BITS + i;
            }

            function sizeInBits(digits) {

                var k = 0,
                    i = 0,
                    j = 0;
                if (cryptoMath.isZero(digits)) {
                    return 0;
                }
                for (k = digits.length - 1; digits[k] === 0; k--) {}
                for (i = cryptoMath.DIGIT_BITS - 1, j = (1 << i); i > 0; j = j >>> 1, i--) {
                    if ((digits[k] & j) !== 0) {
                        break;
                    }
                }
                return k * cryptoMath.DIGIT_BITS + i;
            }

            function millerRabin(number, iterations) {

                var w = number;
                var wminus1 = [];
                cryptoMath.subtract(w, [1], wminus1);

                var a = largestDivisibleByPowerOfTwo(wminus1);

                var m = [];
                cryptoMath.shiftRight(wminus1, m, a);

                var wlen = sizeInBits(w);
                var b;
                var montmul = cryptoMath.MontgomeryMultiplier(w);

                for (var i = 1; i <= iterations; i++) {

                    var status = false;

                    do {
                        b = getRandomOddNumber(wlen);
                    } while (cryptoMath.compareDigits(b, wminus1) >= 0);

                    var z = [];

                    montmul.modExp(b, m, z, true);

                    if (cryptoMath.compareDigits(z, [1]) === 0 || cryptoMath.compareDigits(z, wminus1) === 0) {
                        continue;
                    }

                    for (var j = 1; j < a; j++) {

                        montmul.montgomeryMultiply(z, z, z);

                        if (cryptoMath.compareDigits(z, wminus1) === 0) {
                            status = true;
                            break;
                        }

                        if (cryptoMath.compareDigits(z, [1]) === 0) {
                            return false;
                        }
                    }

                    if (status === false) {
                        return false;
                    }
                }

                return true;
            }

            function generatePrime(bits) {

                var candidate = getRandomOddNumber(bits),
                    inc = 0,
                    possiblePrime,
                    isPrime = false,
                    candidatePlusInc = [];

                setupIncrementalTrialDivision(candidate);

                while (true) {

                    possiblePrime = incrementalTrialDivision(inc);

                    if (possiblePrime) {
                        cryptoMath.add(candidate, [inc], candidatePlusInc);
                        if (millerRabin(candidatePlusInc, 6) === true) {
                            return candidatePlusInc;
                        }
                    }

                    inc += 2;
                }

            }

            function getRandomOddNumber(bits) {

                var numBytes = Math.ceil(bits / 8),
                    bytes = msrcryptoPseudoRandom.getBytes(numBytes),
                    digits;

                bytes[0] |= 128;
                bytes[bytes.length - 1] |= 1;

                return cryptoMath.bytesToDigits(bytes);

            }

            return {
                generatePrime: generatePrime
            };

        })();

        var msrcryptoRsaBase = function(keyStruct) {

            var utils = msrcryptoUtilities,
                keyIsPrivate = keyStruct.hasOwnProperty("n") && keyStruct.hasOwnProperty("d"),
                keyIsCrt = keyStruct.hasOwnProperty("p") && keyStruct.hasOwnProperty("q"),
                modulusLength = keyStruct.n.length;

            function toBytes(digits) {

                var bytes = cryptoMath.digitsToBytes(digits);

                utils.padFront(bytes, 0, modulusLength);

                return bytes;
            }

            function modExp(dataBytes, expBytes, modulusBytes) {
                var exponent = cryptoMath.bytesToDigits(expBytes);

                var group = cryptoMath.IntegerGroup(modulusBytes);
                var base = group.createElementFromBytes(dataBytes);
                var result = group.modexp(base, exponent);

                return result.m_digits;
            }

            function decryptModExp(cipherBytes) {

                var resultElement = modExp(cipherBytes, keyStruct.d, keyStruct.n);

                return toBytes(resultElement);
            }

            function decryptCrt(cipherBytes) {

                var b2d = cryptoMath.bytesToDigits,
                    p = keyStruct.p,
                    q = keyStruct.q,
                    dp = keyStruct.dp,
                    dq = keyStruct.dq,
                    invQ = keyStruct.qi,
                    pDigits = b2d(p),
                    qDigits = b2d(q),
                    temp = new Array(pDigits.length + qDigits.length),
                    m1Digits = new Array(pDigits.length + 1),
                    m2Digits = new Array(qDigits.length + 1),
                    cDigits = b2d(cipherBytes),
                    mm = cryptoMath.MontgomeryMultiplier,
                    mmp = new mm(keyStruct.ctxp ? undefined : pDigits, keyStruct.ctxp),
                    mmq = new mm(keyStruct.ctxq ? undefined : qDigits, keyStruct.ctxq);

                mmp.reduce(cDigits, temp);
                mmp.modExp(temp, b2d(dp), m1Digits);

                mmq.reduce(cDigits, temp);
                mmq.modExp(temp, b2d(dq), m2Digits);

                var carry = cryptoMath.subtract(m1Digits, m2Digits, temp);
                if (carry !== 0) {
                    cryptoMath.subtract(m2Digits, m1Digits, temp);
                }

                cryptoMath.modMul(temp, b2d(invQ), pDigits, cDigits);
                if (carry !== 0) {
                    cryptoMath.subtract(pDigits, cDigits, cDigits);
                }

                cryptoMath.multiply(cDigits, qDigits, temp);
                cryptoMath.add(m2Digits, temp, m1Digits);

                return toBytes(m1Digits);
            }

            return {

                encrypt: function(messageBytes) {

                    var bytes = toBytes(modExp(messageBytes, keyStruct.e, keyStruct.n, true));
                    return bytes;

                },

                decrypt: function(cipherBytes) {

                    if (keyIsCrt) {
                        return decryptCrt(cipherBytes);
                    }

                    if (keyIsPrivate) {
                        return decryptModExp(cipherBytes);
                    }

                    throw new Error("missing private key");
                }
            };

        };

        var rsaShared = {

            mgf1: function(seedBytes, maskLen, hashFunction) {

                var t = [],
                    bytes, hash, counter,
                    hashByteLen = hashFunction.hashLen / 8;

                for (counter = 0; counter <= Math.floor(maskLen / hashByteLen); counter += 1) {

                    bytes = [
                        counter >>> 24 & 0xff,
                        counter >>> 16 & 0xff,
                        counter >>> 8 & 0xff,
                        counter & 0xff
                    ];
                    hash = hashFunction.computeHash(seedBytes.concat(bytes));

                    t = t.concat(hash);
                }

                return t.slice(0, maskLen);
            },

            checkMessageVsMaxHash: function(messageBytes, hashFunction) {

                if (messageBytes.length > (hashFunction.maxMessageSize || 0xFFFFFFFF)) {
                    throw new Error("message too long");
                }

                return;
            }

        };

        var rsaMode = rsaMode || {};

        rsaMode.oaep = function(keyStruct, hashFunction) {

            var utils = msrcryptoUtilities,
                random = msrcryptoPseudoRandom,
                size = keyStruct.n.length;

            if (hashFunction === null) {
                throw new Error("must supply hashFunction");
            }

            function pad(message, label) {

                var lHash, psLen, psArray, i, db, seed;
                var dbMask, maskeddb, seedMask, maskedSeed;
                var encodedMessage;

                if (message.length > (size - 2 * (hashFunction.hashLen / 8) - 2)) {
                    throw new Error("Message too long.");
                }

                if (label == null) {
                    label = [];
                }

                lHash = hashFunction.computeHash(label);

                psLen = size - message.length - (2 * lHash.length) - 2;
                psArray = utils.getVector(psLen);

                db = lHash.concat(psArray, [1], message);

                seed = random.getBytes(lHash.length);

                dbMask = rsaShared.mgf1(seed, size - lHash.length - 1, hashFunction);

                maskeddb = utils.xorVectors(db, dbMask);

                seedMask = rsaShared.mgf1(maskeddb, lHash.length, hashFunction);

                maskedSeed = utils.xorVectors(seed, seedMask);

                encodedMessage = [0].concat(maskedSeed).concat(maskeddb);

                message = encodedMessage.slice();

                return message;
            }

            function unpad(encodedBytes, labelBytes) {

                var lHash, maskedSeed, maskeddb, seedMask;
                var seed, dbMask, db;
                var lHashp, i = 0;
                var valid = encodedBytes[0] === 0;

                if (!labelBytes) {
                    labelBytes = [];
                }

                lHash = hashFunction.computeHash(labelBytes);

                maskedSeed = encodedBytes.slice(1, lHash.length + 1);
                maskeddb = encodedBytes.slice(lHash.length + 1);

                seedMask = rsaShared.mgf1(maskeddb, lHash.length, hashFunction);
                seed = utils.xorVectors(maskedSeed, seedMask);
                dbMask = rsaShared.mgf1(seed, size - lHash.length - 1, hashFunction);

                db = utils.xorVectors(maskeddb, dbMask);

                lHashp = db.slice(0, lHash.length);

                valid = valid && utils.arraysEqual(lHash, lHashp);

                db = db.slice(lHash.length);

                while (!db[i++]) {}

                return {
                    valid: valid,
                    data: db.slice(i)
                };
            }

            return {

                pad: function(messageBytes, labelBytes) {
                    return pad(messageBytes, labelBytes);
                },

                unpad: function(encodedBytes, labelBytes) {
                    return unpad(encodedBytes, labelBytes);
                }
            };

        };

        var msrcryptoRsa = function(keyStruct, mode, hashFunction) {
            var rsaBase = msrcryptoRsaBase(keyStruct);

            if (!mode) {
                throw new Error("padding mode");
            }

            function checkHash() {
                if (!hashFunction || !hashFunction.computeHash) {
                    throw new Error("missing hash function");
                }
            }

            var paddingFunction = null,
                unPaddingFunction = null;

            var padding;

            switch (mode) {

                case "RSAES-PKCS1-V1_5":
                    padding = rsaMode.pkcs1Encrypt(keyStruct);
                    break;

                case "RSASSA-PKCS1-V1_5":
                    checkHash();
                    padding = rsaMode.pkcs1Sign(keyStruct, hashFunction);
                    break;

                case "RSA-OAEP":
                    checkHash();
                    padding = rsaMode.oaep(keyStruct, hashFunction);
                    break;

                case "RSA-PSS":
                    checkHash();
                    padding = rsaMode.pss(keyStruct, hashFunction);
                    break;

                case "raw":
                    padding = {
                        pad: function(mb) {
                            return mb;
                        },
                        unpad: function(eb) {
                            return eb;
                        }
                    };
                    break;

                default:
                    throw new Error("invalid mode");
            }

            if (padding) {
                paddingFunction = padding.pad || padding.sign;
                unPaddingFunction = padding.unpad || padding.verify;
            }

            var returnObj = {
                encrypt: function(dataBytes, labelBytes) {
                    var paddedData;
                    var encryptedData;

                    if (paddingFunction !== null) {
                        paddedData = paddingFunction(dataBytes, labelBytes);
                    } else {
                        paddedData = dataBytes.slice();
                    }

                    encryptedData = rsaBase.encrypt(paddedData);

                    return encryptedData;
                },

                decrypt: function(cipherBytes, labelBytes) {
                    var decryptedData = rsaBase.decrypt(cipherBytes);

                    if (unPaddingFunction !== null) {
                        decryptedData = unPaddingFunction(decryptedData, labelBytes);
                        if (decryptedData.valid === false) {
                            throw new Error("OperationError");
                        }

                        decryptedData = decryptedData.data;

                    } else {
                        decryptedData = decryptedData.slice(0);
                    }

                    return decryptedData;
                },

                signData: function(messageBytes, saltLength, salt) {
                    return rsaBase.decrypt(paddingFunction(messageBytes, saltLength, salt));
                },

                verifySignature: function(
                    signature,
                    messageBytes,
                    saltLength
                ) {
                    var decryptedSig = rsaBase.encrypt(signature);

                    return unPaddingFunction(decryptedSig, messageBytes, saltLength);
                },

                generateKeyPair: function(bits) {
                    var keyPair = genRsaKeyFromRandom(bits);
                },

                mode: mode
            };

            return returnObj;
        };

        if (typeof operations !== "undefined") {
            msrcryptoRsa.sign = function(p) {
                var rsaObj,
                    hashName = p.keyHandle.algorithm.hash.name,
                    hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()](),
                    saltLength = p.algorithm.saltLength,
                    salt = p.algorithm.salt;

                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

                return rsaObj.signData(p.buffer, saltLength, salt);
            };

            msrcryptoRsa.verify = function(p) {
                var hashName = p.keyHandle.algorithm.hash.name,
                    hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()](),
                    rsaObj,
                    saltLength = p.algorithm.saltLength;

                rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);

                return rsaObj.verifySignature(p.signature, p.buffer, saltLength);
            };

            msrcryptoRsa.workerEncrypt = function(p) {
                var result, rsaObj, hashFunc, hashName;

                switch (p.algorithm.name) {

                    case "RSAES-PKCS1-V1_5":
                        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                        result = rsaObj.encrypt(p.buffer);
                        break;

                    case "RSA-OAEP":
                        hashName = p.keyHandle.algorithm.hash.name;
                        if (!hashName) {
                            throw new Error("unsupported hash algorithm");
                        }
                        hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()]();
                        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                        result = rsaObj.encrypt(p.buffer);
                        break;

                    default:
                        throw new Error("unsupported algorithm");
                }

                return result;
            };

            msrcryptoRsa.workerDecrypt = function(p) {
                var result, rsaObj, hashFunc;

                switch (p.algorithm.name) {

                    case "RSAES-PKCS1-V1_5":
                        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name);
                        result = rsaObj.decrypt(p.buffer);
                        break;

                    case "RSA-OAEP":
                        var hashName = p.keyHandle.algorithm.hash.name;
                        if (!hashName) {
                            throw new Error("unsupported hash algorithm");
                        }
                        hashFunc = msrcryptoHashFunctions[hashName.toUpperCase()]();
                        rsaObj = msrcryptoRsa(p.keyData, p.algorithm.name, hashFunc);
                        result = rsaObj.decrypt(p.buffer);
                        break;

                    default:
                        throw new Error("unsupported algorithm");
                }

                return result;
            };

            msrcryptoRsa.importKey = function(p) {

                var keyObject;

                if (p.format === "jwk") {

                    keyObject = msrcryptoJwk.jwkToKey(p.keyData, p.algorithm, ["n", "e", "d", "q", "p", "dq", "dp", "qi"]);

                    if (keyObject.d) {
                        keyObject.ctxp = new cryptoMath.MontgomeryMultiplier(cryptoMath.bytesToDigits(keyObject.p)).ctx;
                        keyObject.ctxq = new cryptoMath.MontgomeryMultiplier(cryptoMath.bytesToDigits(keyObject.q)).ctx;
                    }

                } else if (p.format === "spki") {

                    var publicKeyInfo = asn1.parse(p.keyData);

                    if (publicKeyInfo == null) {
                        throw new Error("invalid key data.");
                    }

                    var bitString = publicKeyInfo[1];
                    var keySequence = asn1.parse(bitString.data.slice(bitString.header + 1), true);

                    if (keySequence == null) {
                        throw new Error("invalid key data.");
                    }

                    var n = keySequence[0],
                        e = keySequence[1];

                    if (n.type !== "INTEGER" || e.type !== "INTEGER") {
                        throw new Error("invalid key data.");
                    }

                    n = n.data.slice(n.header);
                    e = e.data.slice(e.header);

                    if (n[0] === 0 && n[1] & 128) {
                        n = n.slice(1);
                    }
                    if (e[0] === 0 && e[1] & 128) {
                        e = e.slice(1);
                    }

                    keyObject = {
                        n: n,
                        e: e
                    };

                } else {
                    throw new Error("unsupported key import format.");
                }

                return {
                    type: "keyImport",
                    keyData: keyObject,
                    keyHandle: {
                        algorithm: p.algorithm,
                        extractable: p.extractable,
                        usages: p.usages,
                        type: keyObject.d || keyObject.dq ? "private" : "public"
                    }
                };
            };

            msrcryptoRsa.exportKey = function(p) {
                if (p.format === 'spki') {
                    return {
                        type: "keyExport",
                        keyHandle: rsaDer.exportKeyToSpki(p)
                    };
                }

                var jsonKeyStringArray = msrcryptoJwk.keyToJwk(p.keyHandle, p.keyData);

                return {
                    type: "keyExport",
                    keyHandle: jsonKeyStringArray
                };
            };

            msrcryptoRsa.genRsaKeyFromRandom = function(bits, e) {
                var exp = e ? cryptoMath.bytesToDigits(e) : [65537];

                do {
                    var p = prime.generatePrime(bits / 2);

                    var q = prime.generatePrime(bits / 2);

                    if (cryptoMath.compareDigits(q, p) > 0) {
                        var t = p;
                        p = q;
                        q = t;
                    }

                    var n = [];
                    cryptoMath.multiply(p, q, n);

                    var p_1 = [];
                    cryptoMath.subtract(p, [1], p_1);

                    var q_1 = [];
                    cryptoMath.subtract(q, [1], q_1);

                    var p_1q_1 = [];
                    cryptoMath.multiply(p_1, q_1, p_1q_1);

                    var gcd = [];
                    cryptoMath.gcd(exp, p_1q_1, gcd);

                    var gcdEqual1 = cryptoMath.compareDigits(gcd, cryptoMath.One) === 0;

                } while (!gcdEqual1);

                var d = [];
                cryptoMath.modInv(exp, p_1q_1, d);

                var dp = [];
                cryptoMath.reduce(d, p_1, dp);

                var dq = [];
                cryptoMath.reduce(d, q_1, dq);

                var qi = [];
                cryptoMath.modInv(q, p, qi);

                var d2b = cryptoMath.digitsToBytes;

                return {
                    privateKey: {
                        n: d2b(n),
                        e: d2b(exp),
                        d: d2b(d),
                        p: d2b(p),
                        q: d2b(q),
                        dp: d2b(dp),
                        dq: d2b(dq),
                        qi: d2b(qi)
                    },
                    publicKey: {
                        n: d2b(n),
                        e: d2b(exp)
                    }
                };
            };

            msrcryptoRsa.generateKeyPair = function(p) {
                if (typeof p.algorithm.modulusLength === "undefined") {
                    throw new Error("missing modulusLength");
                }

                var keyPair;
                var b2d = cryptoMath.bytesToDigits;

                switch (p.algorithm.modulusLength) {
                    case 1024:
                    case 2048:
                    case 4096:
                        keyPair = msrcryptoRsa.genRsaKeyFromRandom(p.algorithm.modulusLength, p.algorithm.publicExponent);
                        break;
                    default:
                        throw new Error("invalid modulusLength");
                }

                var pk = keyPair.privateKey;
                pk.ctxp = (new cryptoMath.MontgomeryMultiplier(b2d(pk.p))).ctx;
                pk.ctxq = (new cryptoMath.MontgomeryMultiplier(b2d(pk.q))).ctx;

                var algName = p.algorithm.name;
                var rsaKeyType = algName.slice(algName.indexOf("-") + 1).toUpperCase();

                var publicUsage, privateUsage;

                if (algName === "RSASSA-PKCS1-V1_5" || algName === "RSA-PSS") {
                    publicUsage = ["verify"];
                    privateUsage = ["sign"];
                } else {
                    publicUsage = ["encrypt"];
                    privateUsage = ["decrypt"];
                }

                return {
                    type: "keyGeneration",
                    keyPair: {
                        publicKey: {
                            keyData: keyPair.publicKey,
                            keyHandle: {
                                algorithm: p.algorithm,
                                extractable: p.extractable,
                                usages: null || publicUsage,
                                type: "public"
                            }
                        },
                        privateKey: {
                            keyData: keyPair.privateKey,
                            keyHandle: {
                                algorithm: p.algorithm,
                                extractable: p.extractable,
                                usages: null || privateUsage,
                                type: "private"
                            }
                        }
                    }
                };
            };

            operations.register("sign", "RSASSA-PKCS1-V1_5", msrcryptoRsa.sign);
            operations.register("sign", "RSA-PSS", msrcryptoRsa.sign);

            operations.register("verify", "RSASSA-PKCS1-V1_5", msrcryptoRsa.verify);
            operations.register("verify", "RSA-PSS", msrcryptoRsa.verify);

            operations.register("encrypt", "RSAES-PKCS1-V1_5", msrcryptoRsa.workerEncrypt);
            operations.register("decrypt", "RSAES-PKCS1-V1_5", msrcryptoRsa.workerDecrypt);
            operations.register("encrypt", "RSA-OAEP", msrcryptoRsa.workerEncrypt);
            operations.register("decrypt", "RSA-OAEP", msrcryptoRsa.workerDecrypt);

            operations.register("importKey", "RSA-OAEP", msrcryptoRsa.importKey);
            operations.register("importKey", "RSAES-PKCS1-V1_5", msrcryptoRsa.importKey);
            operations.register("importKey", "RSASSA-PKCS1-V1_5", msrcryptoRsa.importKey);
            operations.register("importKey", "RSA-PSS", msrcryptoRsa.importKey);

            operations.register("exportKey", "RSA-OAEP", msrcryptoRsa.exportKey);
            operations.register("exportKey", "RSAES-PKCS1-V1_5", msrcryptoRsa.exportKey);
            operations.register("exportKey", "RSASSA-PKCS1-V1_5", msrcryptoRsa.exportKey);
            operations.register("exportKey", "RSA-PSS", msrcryptoRsa.exportKey);

            operations.register("generateKey", "RSA-OAEP", msrcryptoRsa.generateKeyPair);
            operations.register("generateKey", "RSAES-PKCS1-V1_5", msrcryptoRsa.generateKeyPair);
            operations.register("generateKey", "RSASSA-PKCS1-V1_5", msrcryptoRsa.generateKeyPair);
            operations.register("generateKey", "RSA-PSS", msrcryptoRsa.generateKeyPair);
        }

        var msrcryptoSubtle;

        var utils = msrcryptoUtilities;

        msrcryptoSubtle = (function() {
            function syncWorker() {
                var result;

                function postMessage(data) {

                    try {
                        data.workerid = this.id;
                        result = msrcryptoWorker.jsCryptoRunner({
                            data: data
                        });
                    } catch (ex) {
                        this.onerror({
                            data: ex,
                            type: "error"
                        });
                        return;
                    }

                    this.onmessage({
                        data: result
                    });
                }

                return {
                    postMessage: postMessage,
                    onmessage: null,
                    onerror: null,
                    terminate: function() {}
                };
            }

            var streamObject = function(op) {

                return {
                    process: function(buffer) {
                        return op.process(buffer);
                    },
                    finish: function() {
                        return op.finish();
                    },
                    abort: function() {
                        return op.abort();
                    }
                };
            };

            function baseOperation(processResults) {

                var result = null,
                    oncompleteCallback = null,
                    onerrorCallback = null,
                    retObj,
                    promise,
                    resolveFunc,
                    rejectFunc;

                promise = new Promise(
                    function(resolve, reject) {
                        resolveFunc = resolve;
                        rejectFunc = reject;
                    });

                function opDispatchEvent(e) {
                    if (e.type === "error") {
                        if (rejectFunc) {
                            rejectFunc.apply(promise, [e]);
                        }
                        return;
                    }

                    if (e.data.type === "process") {
                        processResults(e.data.result, true);
                        return;
                    }

                    if (e.data.type === "finish") {
                        processResults(e.data.result, true);
                        return;
                    }

                    this.result = processResults(e.data);
                    resolveFunc.apply(promise, [this.result]);

                    return;
                }

                retObj = {
                    dispatchEvent: opDispatchEvent,
                    promise: promise,
                    result: null
                };

                return retObj;
            }

            function keyOperation() {

                function processResult(result) {

                    var publicKey,
                        privateKey;

                    switch (result.type) {

                        case "keyGeneration":
                        case "keyImport":
                        case "keyDerive":
                            if (result.keyPair) {
                                keys.add(result.keyPair.publicKey.keyHandle, result.keyPair.publicKey.keyData);
                                keys.add(result.keyPair.privateKey.keyHandle, result.keyPair.privateKey.keyData);
                                return {
                                    publicKey: result.keyPair.publicKey.keyHandle,
                                    privateKey: result.keyPair.privateKey.keyHandle
                                };
                            } else {
                                keys.add(result.keyHandle, result.keyData);
                                return result.keyHandle;
                            }

                            case "keyExport":
                                return result.keyHandle;

                            case "keyPairGeneration":
                                privateKey = result.keyPair.privateKey;
                                publicKey = result.keyPair.publicKey;
                                keys.add(publicKey.keyHandle, publicKey.keyData);
                                keys.add(privateKey.keyHandle, privateKey.keyData);
                                return {
                                    publicKey: publicKey.keyHandle,
                                        privateKey: privateKey.keyHandle
                                };

                            default:
                                throw new Error("Unknown key operation");
                    }
                }

                return baseOperation(processResult);
            }

            function toArrayBufferIfSupported(dataArray) {

                if (typedArraySupport && dataArray.pop) {

                    return (new Uint8Array(dataArray)).buffer;
                }

                return dataArray;
            }

            function cryptoOperation(cryptoContext) {

                function processResult(result, isProcessCall) {

                    result = result && toArrayBufferIfSupported(result);

                    if (isProcessCall) {
                        promiseQueue.resolve(result);
                        return;
                    }

                    return result;
                }

                var promiseQueue = [],
                    op = baseOperation(processResult);

                op.stream = cryptoContext.algorithm.stream;

                promiseQueue.add = function(label) {

                    var resolveFunc,
                        rejectFunc,
                        promise = new Promise(
                            function(resolve, reject) {
                                resolveFunc = resolve;
                                rejectFunc = reject;
                            });

                    promise.label = label;

                    promiseQueue.push({
                        resolve: resolveFunc,
                        reject: rejectFunc,
                        promise: promise
                    });

                    return promise;
                };

                promiseQueue.resolve = function(result) {
                    var queueItem = promiseQueue.shift();
                    queueItem.resolve.apply(queueItem.promise, [result]);
                };

                op.process = function(buffer) {
                    cryptoContext.operationSubType = "process";
                    cryptoContext.buffer = utils.toArray(buffer);
                    workerManager.continueJob(this,
                        utils.clone(cryptoContext));

                    return promiseQueue.add("process");
                };

                op.finish = function() {
                    cryptoContext.operationSubType = "finish";
                    cryptoContext.buffer = [];
                    workerManager.continueJob(this,
                        utils.clone(cryptoContext));

                    return promiseQueue.add("finish");
                };

                op.abort = function() {
                    workerManager.abortJob(this);
                };
                op.algorithm = cryptoContext.algorithm || null;
                op.key = cryptoContext.keyHandle || null;

                return op;
            }

            var keys = [];

            keys.add = function(keyHandle, keyData) {
                keys.push({
                    keyHandle: keyHandle,
                    keyData: keyData
                });
            };

            keys.remove = function(keyHandle) {
                for (var i = 0; i < keys.length; i += 1) {
                    if (keys[i].keyHandle === keyHandle) {
                        keys = keys.splice(i, 1);
                        return;
                    }
                }
            };

            keys.lookup = function(keyHandle) {
                for (var i = 0; i < keys.length; i += 1) {
                    if (keys[i].keyHandle === keyHandle) {
                        return keys[i].keyData;
                    }
                }
                return null;
            };

            var workerManager = (function() {

                var maxWorkers = 12;

                var maxFreeWorkers = 2;

                var workerPool = [];

                var jobQueue = [];

                var jobId = 0;

                var workerId = 0;

                var callbackQueue = [];

                var setFunction = typeof setImmediate === "undefined" ? setTimeout : setImmediate;

                function executeNextCallback() {
                    callbackQueue.shift()();
                }

                function queueCallback(callback) {
                    callbackQueue.push(callback);
                    setFunction(executeNextCallback, 0);
                }

                var workerStatus = webWorkerSupport ? "available" : "unavailable";

                function getFreeWorker() {

                    purgeWorkerType(!asyncMode);

                    for (var i = 0; i < workerPool.length; i++) {
                        if (!workerPool[i].busy) {
                            return workerPool[i];
                        }
                    }

                    return null;
                }

                function purgeWorkerType(webWorker) {
                    for (var i = workerPool.length - 1; i >= 0; i -= 1) {
                        if (workerPool[i].isWebWorker === webWorker) {
                            workerPool[i].terminate();
                            workerPool.splice(i, 1);
                        }
                    }
                }

                function freeWorkerCount() {
                    var freeWorkers = 0;
                    for (var i = 0; i < workerPool.length; i++) {
                        if (!workerPool[i].busy) {
                            freeWorkers += 1;
                        }
                    }
                    return freeWorkers;
                }

                function addWorkerToPool(worker) {
                    workerPool.push(worker);
                }

                function removeWorkerFromPool(worker) {
                    for (var i = 0; i < workerPool.length; i++) {
                        if (workerPool[i] === worker) {
                            worker.terminate();
                            workerPool.splice(i, 1);
                            return;
                        }
                    }
                }

                function lookupWorkerByOperation(operation) {
                    for (var i = 0; i < workerPool.length; i++) {
                        if (workerPool[i].operation === operation) {
                            return workerPool[i];
                        }
                    }
                    return null;
                }

                function queueJob(operation, data) {
                    jobQueue.push({
                        operation: operation,
                        data: data,
                        id: jobId++
                    });
                }

                function jobCompleted(worker) {

                    worker.busy = false;

                    if (asyncMode) {
                        if (jobQueue.length > 0) {

                            var job = jobQueue.shift(),
                                i;

                            continueJob(job.operation, job.data);

                            if (job.data.operationSubType === "process") {
                                for (i = 0; i < jobQueue.length; i++) {
                                    if (job.operation === jobQueue[i].operation) {
                                        continueJob(jobQueue[i].operation, jobQueue[i].data);
                                    }
                                }
                                for (i = jobQueue.length - 1; i >= 0; i--) {
                                    if (job.operation === jobQueue[i].operation) {
                                        jobQueue.splice(i, 1);
                                    }
                                }
                            }
                        } else if (freeWorkerCount() > maxFreeWorkers) {
                            removeWorkerFromPool(worker);
                        }
                    }

                }

                function createNewWorker(operation) {

                    var worker;

                    if (workerStatus === "pending") {
                        throw new Error("Creating new worker while workerstatus=pending");
                    }

                    if (workerStatus === "ready") {
                        try {
                            worker = new Worker(scriptUrl);
                            worker.postMessage({
                                prngSeed: msrcryptoPseudoRandom.getBytes(48)
                            });
                            worker.isWebWorker = true;
                        } catch (ex) {
                            asyncMode = false;
                            workerStatus = "failed";
                            worker.terminate();
                            worker = syncWorker();
                            worker.isWebWorker = false;
                        }

                    } else {
                        worker = syncWorker();
                        worker.isWebWorker = false;
                    }

                    worker.operation = operation;

                    worker.id = workerId++;

                    worker.busy = false;

                    worker.onmessage = function(e) {

                        if (e.data.initialized === true) {
                            return;
                        }

                        var op = worker.operation;

                        e.target || (e.target = {
                            data: worker.data
                        });

                        for (var i = 0; i < jobQueue.length; i++) {
                            if (jobQueue[i].operation === worker.operation) {
                                var job = jobQueue[i];
                                jobQueue.splice(i, 1);
                                postMessageToWorker(worker, job.data);
                                return;
                            }
                        }

                        if (!(e.data.hasOwnProperty("type") && e.data.type === "process")) {
                            jobCompleted(worker);
                        }

                        op.dispatchEvent(e);
                    };

                    worker.onerror = function(e) {

                        var op = worker.operation;

                        jobCompleted(worker);

                        op.dispatchEvent(e);
                    };

                    addWorkerToPool(worker);

                    return worker;
                }

                function useWebWorkers(enable) {
                    if (workerStatus === "unavailable") {
                        utils.consoleLog("web workers not available in this browser.");
                        return;
                    }

                    if (enable === true && workerStatus === "ready") {
                        return;
                    }

                    if (enable === false && workerStatus === "available") {
                        return;
                    }

                    if (enable === false && workerStatus === "ready") {
                        asyncMode = false;
                        workerStatus = "available";
                        utils.consoleLog("web workers disabled.");
                        return;
                    }

                    if (workerStatus === "pending") {
                        return;
                    }

                    workerStatus = "pending";

                    var worker = new Worker(scriptUrl);

                    function setWorkerStatus(e) {
                        var succeeded = !!(e.data && e.data.initialized === true);
                        worker.removeEventListener("message", setWorkerStatus, false);
                        worker.removeEventListener("error", setWorkerStatus, false);
                        worker.terminate();
                        workerStatus = succeeded ? "ready" : "failed";
                        asyncMode = succeeded;
                        utils.consoleLog("web worker initialization " + (succeeded ? "succeeded. Now using web workers." :
                            "failed. running synchronously." + (e.message || "")));
                        if (jobQueue.length > 0) {
                            var job = jobQueue.shift();
                            runJob(job.operation, job.data);
                        }
                        return;
                    }

                    worker.addEventListener("message", setWorkerStatus, false);
                    worker.addEventListener("error", setWorkerStatus, false);

                    worker.postMessage({
                        prngSeed: msrcryptoPseudoRandom.getBytes(48)
                    });

                    return;
                }

                function abortJob(cryptoOperationObject) {
                    var worker = lookupWorkerByOperation(cryptoOperationObject);
                    if (worker) {
                        removeWorkerFromPool(worker);
                    }
                }

                function runJob(operation, data) {

                    var worker = null;

                    if (workerStatus === "pending") {
                        queueJob(operation, data);
                        return;
                    }

                    worker = getFreeWorker();

                    if (asyncMode && worker === null && workerPool.length >= maxWorkers) {
                        queueJob(operation, data);
                        return;
                    }

                    if (worker === null) {
                        worker = createNewWorker(operation);
                    }

                    if (worker === null) {
                        queueJob(operation, data);
                        throw new Error("could not create new worker");
                    }

                    worker.operation = operation;

                    worker.busy = true;

                    data.workerid = worker.id;

                    postMessageToWorker(worker, data);
                }

                function continueJob(operation, data) {

                    var worker = lookupWorkerByOperation(operation);

                    if (worker) {
                        postMessageToWorker(worker, data);
                        return;
                    }

                    runJob(operation, data);
                }

                function postMessageToWorker(worker, data) {
                    data.workerid = worker.id;

                    if (asyncMode) {

                        worker.postMessage(data);

                    } else {

                        var func = (function(postData) {
                            return function() {
                                return worker.postMessage(postData);
                            };
                        })(data);

                        queueCallback(func);
                    }

                    return;
                }

                return {
                    runJob: runJob,
                    continueJob: continueJob,
                    abortJob: abortJob,
                    useWebWorkers: useWebWorkers
                };

            })();

            function checkOperation(operationType, algorithmName) {
                if (!operations.exists(operationType, algorithmName)) {
                    throw new Error("unsupported algorithm");
                }
            }

            var subtleParameters = [{
                    name: "algorithm",
                    type: "Object",
                    required: true
                },
                {
                    name: "keyHandle",
                    type: "Object",
                    required: true
                },
                {
                    name: "buffer",
                    type: "Array",
                    required: false
                },
                {
                    name: "signature",
                    type: "Array",
                    required: true
                },
                {
                    name: "format",
                    type: "String",
                    required: true
                },
                {
                    name: "keyData",
                    type: "Object",
                    required: true
                },
                {
                    name: "extractable",
                    type: "Boolean",
                    required: false
                },
                {
                    name: "usages",
                    type: "Array",
                    required: false
                },
                {
                    name: "derivedKeyType",
                    type: "Object",
                    required: true
                },
                {
                    name: "length",
                    type: "Number",
                    required: false
                },
                {
                    name: "extractable",
                    type: "Boolean",
                    required: true
                },
                {
                    name: "usages",
                    type: "Array",
                    required: true
                },
                {
                    name: "keyData",
                    type: "Array",
                    required: true
                }
            ];

            var subtleParametersSets = {
                encrypt: [0, 1, 2],
                decrypt: [0, 1, 2],
                sign: [0, 1, 2],
                verify: [0, 1, 3, 2],
                digest: [0, 2],
                generateKey: [0, 6, 7],
                importKeyRaw: [4, 12, 0, 10, 11],
                importKeyJwk: [4, 5, 0, 10, 11],
                exportKey: [0, 4, 1, 6, 7],
                deriveKey: [0, 1, 8, 6, 7],
                deriveBits: [0, 1, 9],
                wrapKey: [1, 1, 0],
                unwrapKey: [2, 0, 1, 6, 7]
            };

            function lookupKeyData(handle) {
                var data = keys.lookup(handle);

                if (!data) {
                    throw new Error("key not found");
                }

                return data;
            }

            function buildParameterCollection(operationName, parameterSet) {

                var parameterCollection = {
                        operationType: operationName
                    },
                    operationParameterSet,
                    expectedParam,
                    actualParam,
                    i;

                if (operationName === "importKey" && (parameterSet[0] === "raw" || parameterSet[0] === "spki")) {
                    operationName = "importKeyRaw";
                }

                if (operationName === "importKey" && parameterSet[0] === "jwk") {
                    operationName = "importKeyJwk";
                }

                operationParameterSet = subtleParametersSets[operationName];

                for (i = 0; i < operationParameterSet.length; i += 1) {

                    expectedParam = subtleParameters[operationParameterSet[i]];
                    actualParam = parameterSet[i];

                    if (actualParam == null) {
                        if (expectedParam.required) {
                            throw new Error(expectedParam.name);
                        } else {
                            continue;
                        }
                    }

                    if (actualParam.subarray) {
                        actualParam = utils.toArray(actualParam);
                    }

                    if (utils.getObjectType(actualParam) === "ArrayBuffer") {
                        actualParam = utils.toArray(actualParam);
                    }

                    if (msrcryptoUtilities.getObjectType(actualParam) !== expectedParam.type) {
                        throw new Error(expectedParam.name);
                    }

                    if (expectedParam.name === "algorithm") {

                        actualParam.name = actualParam.name.toUpperCase();

                        if (actualParam.iv) {
                            actualParam.iv = utils.toArray(actualParam.iv);
                        }

                        if (actualParam.publicExponent) {
                            actualParam.publicExponent = utils.toArray(actualParam.publicExponent);
                        }

                        if (actualParam.salt) {
                            actualParam.salt = utils.toArray(actualParam.salt);
                        }

                        if (actualParam.additionalData) {
                            actualParam.additionalData = utils.toArray(actualParam.additionalData);
                        }

                        if (actualParam.hash && !actualParam.hash.name && utils.getObjectType(actualParam.hash) === "String") {
                            actualParam.hash = {
                                name: actualParam.hash
                            };
                        }
                    }

                    if (parameterCollection.hasOwnProperty(expectedParam.name)) {
                        parameterCollection[expectedParam.name + "1"] = actualParam;
                    } else {
                        parameterCollection[expectedParam.name] = actualParam;
                    }
                }

                return parameterCollection;
            }

            function executeOperation(operationName, parameterSet, keyFunc) {

                var pc = buildParameterCollection(operationName, parameterSet);

                checkOperation(operationName, pc.algorithm.name);

                if (pc.keyHandle) {
                    pc.keyData = lookupKeyData(pc.keyHandle);
                }

                if (pc.keyHandle1) {
                    pc.keyData1 = lookupKeyData(pc.keyHandle1);
                }

                if (pc.algorithm && pc.algorithm.public) {
                    pc.additionalKeyData = lookupKeyData(pc.algorithm.public);
                }

                var op = keyFunc ? keyOperation(pc) : cryptoOperation(pc);

                if (keyFunc || pc.buffer || operationName === "deriveBits" || operationName === "wrapKey") {
                    workerManager.runJob(op, pc);
                }

                if (op.stream) {
                    return Promise.resolve(streamObject(op));
                }

                return op.promise;
            }
            var publicMethods = {

                encrypt: function(algorithm, keyHandle, buffer) {
                    return executeOperation("encrypt", arguments, 0);
                },

                decrypt: function(algorithm, keyHandle, buffer) {
                    return executeOperation("decrypt", arguments, 0);
                },

                sign: function(algorithm, keyHandle, buffer) {
                    return executeOperation("sign", arguments, 0);
                },

                verify: function(algorithm, keyHandle, signature, buffer) {
                    return executeOperation("verify", arguments, 0);
                },

                digest: function(algorithm, buffer) {
                    return executeOperation("digest", arguments, 0);
                },

                generateKey: function(algorithm, extractable, keyUsage) {
                    return executeOperation("generateKey", arguments, 1);
                },

                deriveKey: function(algorithm, baseKey, derivedKeyType, extractable, keyUsage) {
                    var deriveBits = this.deriveBits,
                        importKey = this.importKey;

                    return new Promise(function(resolve, reject) {

                        var keyLength;

                        switch (derivedKeyType.name.toUpperCase()) {
                            case "AES-CBC":
                            case "AES-GCM":
                                keyLength = derivedKeyType.length;
                                break;
                            case "HMAC":
                                keyLength = derivedKeyType.length || {
                                    "SHA-1": 512,
                                    "SHA-224": 512,
                                    "SHA-256": 512,
                                    "SHA-384": 1024,
                                    "SHA-512": 1024
                                } [derivedKeyType.hash.name.toUpperCase()];
                                break;
                            default:
                                reject(new Error("No Supported"));
                                return;
                        }

                        deriveBits(algorithm, baseKey, keyLength)
                            .then(function(bits) {
                                return importKey("raw", bits, derivedKeyType, extractable, keyUsage);
                            })
                            .then(function(key) {
                                resolve(key);
                            })["catch"](function(err) {
                                reject(err);
                            });

                    });

                },

                deriveBits: function(algorithm, baseKey, length) {
                    return executeOperation("deriveBits", arguments, 0);
                },

                importKey: function(format, keyData, algorithm, extractable, keyUsage) {
                    return executeOperation("importKey", arguments, 1);
                },

                exportKey: function(format, keyHandle) {
                    return executeOperation("exportKey", [keyHandle.algorithm, format, keyHandle], 1);
                },

                wrapKey: function(format, key, wrappingKey, wrappingKeyAlgorithm) {
                    var encrypt = this.encrypt,
                        exportKey = this.exportKey;

                    return new Promise(function(resolve, reject) {

                        if (key.extractable === false ||
                            key.usages.indexOf("wrapKey") < 0 ||
                            wrappingKey.algorithm.name.toUpperCase() !== wrappingKeyAlgorithm.name) {
                            reject(new Error("InvalidAccessError"));
                            return;
                        }

                        exportKey(format, key)

                            .then(function(keyData) {
                                return encrypt(wrappingKeyAlgorithm, wrappingKey, format === "jwk" ?
                                    utils.stringToBytes(JSON.stringify(keyData, null, 0)) : keyData);
                            })

                            .then(function(cipherArrayBuffer) {
                                resolve(cipherArrayBuffer);
                            })

                        ["catch"](function(err) {
                            reject(err);
                        });
                    });
                },

                unwrapKey: function(format, wrappedKey, unwrappingKey, unwrapAlgorithm, unwrappedKeyAlgorithm, extractable, keyUsages) {
                    var decrypt = this.decrypt,
                        importKey = this.importKey;

                    return new Promise(function(resolve, reject) {

                        if (unwrappingKey.usages.indexOf("unwrapKey") < 0 ||
                            unwrappingKey.algorithm.name.toUpperCase() !== unwrapAlgorithm.name) {
                            reject(new Error("InvalidAccessError"));
                            return;
                        }

                        decrypt(unwrapAlgorithm, unwrappingKey, wrappedKey)

                            .then(function(keyPlain) {
                                return importKey(format, format === "jwk" ? JSON.parse(utils.bytesToString(keyPlain)) : keyPlain,
                                    unwrappedKeyAlgorithm, extractable, keyUsages);
                            })

                            .then(function(key) {
                                resolve(key);
                            })

                        ["catch"](function(err) {
                            reject(err);
                        });
                    });

                }

            };

            var internalMethods = {
                useWebWorkers: workerManager.useWebWorkers
            };

            return {
                publicMethods: publicMethods,
                internalMethods: internalMethods
            };

        })();
        var rsaDer = (function() {
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

            function lPadInteger(i) {
                if (i[0] >> 7) {
                    return [0].concat(i)
                } else {
                    return i;
                }
            }

            function exportKeyToSpki(p) {
                var n = lPadInteger(p.keyData.n)
                var e = lPadInteger(p.keyData.e)
                var nDer = [].concat(realAsn1Types.INTEGER, getLenDer(n.length), n)
                var eDer = [].concat(realAsn1Types.INTEGER, getLenDer(e.length), e)
                var keySequenceSeqDer = [].concat(realAsn1Types.SEQUENCE, getLenDer(nDer.length + eDer.length), nDer, eDer)

                var keySequenceSeqBitStringDer = [].concat(realAsn1Types.BITSTRING, getLenDer(keySequenceSeqDer.length + 1), [0], keySequenceSeqDer)

                var publicKeyInfoDer = [].concat(realAsn1Types.SEQUENCE,
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

        var publicMethods = {

            subtle: msrcryptoSubtle ? msrcryptoSubtle.publicMethods : null,

            getRandomValues: function(array) {
                var i;
                var randomValues = msrcryptoPseudoRandom.getBytes(array.length);
                for (i = 0; i < array.length; i += 1) {
                    array[i] = randomValues[i];
                }
                return array;
            },

            initPrng: function(entropyData) {
                var entropyDataType = Object.prototype.toString.call(entropyData);

                if (entropyDataType !== "[object Array]" && entropyDataType !== "[object Uint8Array]") {
                    throw new Error("entropyData must be a Array or Uint8Array");
                }

                entropyPool && entropyPool.reseed(entropyData);

                msrcryptoPseudoRandom.reseed(entropyPool.read(48));
                fprngEntropyProvided = true;
            },

            toBase64: function(data, base64Url) {
                return msrcryptoUtilities.toBase64(data, base64Url);
            },

            fromBase64: function(base64String) {
                return msrcryptoUtilities.fromBase64(base64String);
            },

            textToBytes: function(text) {
                return msrcryptoUtilities.stringToBytes(text);
            },

            bytesToText: function(byteArray) {
                return msrcryptoUtilities.bytesToString(byteArray);
            },

            asn1: asn1,

            url: scriptUrl,

            version: msrCryptoVersion,

            useWebWorkers: function(useWebWorkers) {
                return msrcryptoSubtle ? msrcryptoSubtle.internalMethods.useWebWorkers(useWebWorkers) : null;
            }
        };


        var entropyPool;

        entropyPool = entropyPool || new MsrcryptoEntropy(global);

        entropyPool.init();
        var localEntropy = entropyPool.read(48);
        msrcryptoPseudoRandom.init(localEntropy);
        return publicMethods;

    }

    return msrCrypto();

}));