from Emulator.dvm.JniConst import *
from Emulator.utils.Memory_Helpers import *


class JniHooks:
    # https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/jniTOC.html
    def __init__(self, hooker, vm):
        self.vm = vm
        self.JniEnvAddr, self.JniEnvTableAddr = hooker.write_function_table({
            4: self._GetVersion,
            5: self._DefineClass,
            6: self._FindClass,
            7: self._FromReflectedMethod,
            8: self._FromReflectedField,
            9: self._ToReflectedMethod,
            10: self._GetSuperclass,
            11: self._IsAssignableFrom,
            12: self._ToReflectedField,
            13: self._Throw,
            14: self._ThrowNew,
            15: self._ExceptionOccurred,
            16: self._ExceptionDescribe,
            17: self._ExceptionClear,
            18: self._FatalError,
            19: self._PushLocalFrame,
            20: self._PopLocalFrame,
            21: self._NewGlobalRef,
            22: self._DeleteGlobalRef,
            23: self._DeleteLocalRef,
            24: self._IsSameObject,
            25: self._NewLocalRef,
            26: self._EnsureLocalCapacity,
            27: self._AllocObject,
            28: self._NewObject,
            29: self._NewObjectV,
            30: self._NewObjectA,
            31: self._GetObjectClass,
            32: self._IsInstanceOf,
            33: self._GetMethodID,
            34: self._CallObjectMethod,
            35: self._CallObjectMethodV,
            36: self._CallObjectMethodA,
            37: self._CallBooleanMethod,
            38: self._CallBooleanMethodV,
            39: self._CallBooleanMethodA,
            40: self._CallByteMethod,
            41: self._CallByteMethodV,
            42: self._CallByteMethodA,
            43: self._CallCharMethod,
            44: self._CallCharMethodV,
            45: self._CallCharMethodA,
            46: self._CallShortMethod,
            47: self._CallShortMethodV,
            48: self._CallShortMethodA,
            49: self._CallIntMethod,
            50: self._CallIntMethodV,
            51: self._CallIntMethodA,
            52: self._CallLongMethod,
            53: self._CallLongMethodV,
            54: self._CallLongMethodA,
            55: self._CallFloatMethod,
            56: self._CallFloatMethodV,
            57: self._CallFloatMethodA,
            58: self._CallDoubleMethod,
            59: self._CallDoubleMethodV,
            60: self._CallDoubleMethodA,
            61: self._CallVoidMethod,
            62: self._CallVoidMethodV,
            63: self._CallVoidMethodA,
            64: self._CallNonvirtualObjectMethod,
            65: self._CallNonvirtualObjectMethodV,
            66: self._CallNonvirtualObjectMethodA,
            67: self._CallNonvirtualBooleanMethod,
            68: self._CallNonvirtualBooleanMethodV,
            69: self._CallNonvirtualBooleanMethodA,
            70: self._CallNonvirtualByteMethod,
            71: self._CallNonvirtualByteMethodV,
            72: self._CallNonvirtualByteMethodA,
            73: self._CallNonvirtualCharMethod,
            74: self._CallNonvirtualCharMethodV,
            75: self._CallNonvirtualCharMethodA,
            76: self._CallNonvirtualShortMethod,
            77: self._CallNonvirtualShortMethodV,
            78: self._CallNonvirtualShortMethodA,
            79: self._CallNonvirtualIntMethod,
            80: self._CallNonvirtualIntMethodV,
            81: self._CallNonvirtualIntMethodA,
            82: self._CallNonvirtualLongMethod,
            83: self._CallNonvirtualLongMethodV,
            84: self._CallNonvirtualLongMethodA,
            85: self._CallNonvirtualFloatMethod,
            86: self._CallNonvirtualFloatMethodV,
            87: self._CallNonvirtualFloatMethodA,
            88: self._CallNonvirtualDoubleMethod,
            89: self._CallNonvirtualDoubleMethodV,
            90: self._CallNonvirtualDoubleMethodA,
            91: self._CallNonvirtualVoidMethod,
            92: self._CallNonvirtualVoidMethodV,
            93: self._CallNonvirtualVoidMethodA,
            94: self._GetFieldID,
            95: self._GetObjectField,
            96: self._GetBooleanField,
            97: self._GetByteField,
            98: self._GetCharField,
            99: self._GetShortField,
            100: self._GetIntField,
            101: self._GetLongField,
            102: self._GetFloatField,
            103: self._GetDoubleField,
            104: self._SetObjectField,
            105: self._SetBooleanField,
            106: self._SetByteField,
            107: self._SetCharField,
            108: self._SetShortField,
            109: self._SetIntField,
            110: self._SetLongField,
            111: self._SetFloatField,
            112: self._SetDoubleField,
            113: self._GetStaticMethodID,
            114: self._CallStaticObjectMethod,
            115: self._CallStaticObjectMethodV,
            116: self._CallStaticObjectMethodA,
            117: self._CallStaticBooleanMethod,
            118: self._CallStaticBooleanMethodV,
            119: self._CallStaticBooleanMethodA,
            120: self._CallStaticByteMethod,
            121: self._CallStaticByteMethodV,
            122: self._CallStaticByteMethodA,
            123: self._CallStaticCharMethod,
            124: self._CallStaticCharMethodV,
            125: self._CallStaticCharMethodA,
            126: self._CallStaticShortMethod,
            127: self._CallStaticShortMethodV,
            128: self._CallStaticShortMethodA,
            129: self._CallStaticIntMethod,
            130: self._CallStaticIntMethodV,
            131: self._CallStaticIntMethodA,
            132: self._CallStaticLongMethod,
            133: self._CallStaticLongMethodV,
            134: self._CallStaticLongMethodA,
            135: self._CallStaticFloatMethod,
            136: self._CallStaticFloatMethodV,
            137: self._CallStaticFloatMethodA,
            138: self._CallStaticDoubleMethod,
            139: self._CallStaticDoubleMethodV,
            140: self._CallStaticDoubleMethodA,
            141: self._CallStaticVoidMethod,
            142: self._CallStaticVoidMethodV,
            143: self._CallStaticVoidMethodA,
            144: self._GetStaticFieldID,
            145: self._GetStaticObjectField,
            146: self._GetStaticBooleanField,
            147: self._GetStaticByteField,
            148: self._GetStaticCharField,
            149: self._GetStaticShortField,
            150: self._GetStaticIntField,
            151: self._GetStaticLongField,
            152: self._GetStaticFloatField,
            153: self._GetStaticDoubleField,
            154: self._SetStaticObjectField,
            155: self._SetStaticBooleanField,
            156: self._SetStaticByteField,
            157: self._SetStaticCharField,
            158: self._SetStaticShortField,
            159: self._SetStaticIntField,
            160: self._SetStaticLongField,
            161: self._SetStaticFloatField,
            162: self._SetStaticDoubleField,
            163: self._NewString,
            164: self._GetStringLength,
            165: self._GetStringChars,
            166: self._ReleaseStringChars,
            167: self._NewStringUTF,
            168: self._GetStringUTFLength,
            169: self._GetStringUTFChars,
            170: self._ReleaseStringUTFChars,
            171: self._GetArrayLength,
            172: self._NewObjectArray,
            173: self._GetObjectArrayElement,
            174: self._SetObjectArrayElement,
            175: self._NewBooleanArray,
            176: self._NewByteArray,
            177: self._NewCharArray,
            178: self._NewShortArray,
            179: self._NewIntArray,
            180: self._NewLongArray,
            181: self._NewFloatArray,
            182: self._NewDoubleArray,
            183: self._GetBooleanArrayElements,
            184: self._GetByteArrayElements,
            185: self._GetCharArrayElements,
            186: self._GetShortArrayElements,
            187: self._GetIntArrayElements,
            188: self._GetLongArrayElements,
            189: self._GetFloatArrayElements,
            190: self._GetDoubleArrayElements,
            191: self._ReleaseBooleanArrayElements,
            192: self._ReleaseByteArrayElements,
            193: self._ReleaseCharArrayElements,
            194: self._ReleaseShortArrayElements,
            195: self._ReleaseIntArrayElements,
            196: self._ReleaseLongArrayElements,
            197: self._ReleaseFloatArrayElements,
            198: self._ReleaseDoubleArrayElements,
            199: self._GetBooleanArrayRegion,
            200: self._GetByteArrayRegion,
            201: self._GetCharArrayRegion,
            202: self._GetShortArrayRegion,
            203: self._GetIntArrayRegion,
            204: self._GetLongArrayRegion,
            205: self._GetFloatArrayRegion,
            206: self._GetDoubleArrayRegion,
            207: self._SetBooleanArrayRegion,
            208: self._SetByteArrayRegion,
            209: self._SetCharArrayRegion,
            210: self._SetShortArrayRegion,
            211: self._SetIntArrayRegion,
            212: self._SetLongArrayRegion,
            213: self._SetFloatArrayRegion,
            214: self._SetDoubleArrayRegion,
            215: self._RegisterNatives,
            216: self._UnregisterNatives,
            217: self._MonitorEnter,
            218: self._MonitorExit,
            219: self._GetJavaVM,
            220: self._GetStringRegion,
            221: self._GetStringUTFRegion,
            222: self._GetPrimitiveArrayCritical,
            223: self._ReleasePrimitiveArrayCritical,
            224: self._GetStringCritical,
            225: self._ReleaseStringCritical,
            226: self._NewWeakGlobalRef,
            227: self._DeleteWeakGlobalRef,
            228: self._ExceptionCheck,
            229: self._NewDirectByteBuffer,
            230: self._GetDirectBufferAddress,
            231: self._GetDirectBufferCapacity,
            232: self._GetObjectRefType
        })
        self.JavaVMAddr, self.JavaVMTableAddr = hooker.write_function_table({
            3: self._DestroyJavaVM,
            4: self._AttachCurrentThread,
            5: self._DetachCurrentThread,
            6: self._GetEnv,
            7: self._AttachCurrentThreadAsDaemon
        })

    def _DestroyJavaVM(self, mu):
        raise NotImplementedError()

    def _AttachCurrentThread(self, mu):
        raise NotImplementedError()

    def _DetachCurrentThread(self, mu):
        raise NotImplementedError()

    def _GetEnv(self, mu):
        vm = getPointerArg(mu, 0)
        env = getPointerArg(mu, 1)
        version = getPointerArg(mu, 3)
        mu.mem_write(env, self.JniEnvAddr)
        return JNI_OK

    def _AttachCurrentThreadAsDaemon(self, mu):
        raise NotImplementedError()

    def _GetVersion(self, mu):
        raise NotImplementedError()

    def _DefineClass(self, mu):
        raise NotImplementedError()

    def _FindClass(self, mu):
        className = getPointerArg(mu, 1)
        name = read_utf8(mu, className)
        dvmClass = self.vm.resolveClass(name)
        h = dvmClass.hashCode() & 0xffffffff
        return h

    def _FromReflectedMethod(self, mu):
        raise NotImplementedError()

    def _FromReflectedField(self, mu):
        raise NotImplementedError()

    def _ToReflectedMethod(self, mu):
        clazz = getPointerArg(mu, 1)
        jmethodID = getPointerArg(mu, 2)
        h = clazz & 0xffffffff
        if h in self.vm.classMaps:
            dvmClass = self.vm.classMaps[h]
            mh = jmethodID & 0xffffffff
            dvmMethod = dvmClass.getMethod()
            if dvmMethod is None:
                dvmMethod = dvmClass.getMethod(mh, True)
            if dvmMethod is not None:
                return self.vm.addObject(dvmMethod, False)
            else:
                raise Exception('Method Not Found hash 0x%x' % mh)
        else:
            raise Exception('Class Not Found hash 0x%x' % h)

    def _GetSuperclass(self, mu):
        raise NotImplementedError()

    def _IsAssignableFrom(self, mu):
        raise NotImplementedError()

    def _ToReflectedField(self, mu):
        raise NotImplementedError()

    def _Throw(self, mu):
        raise NotImplementedError()

    def _ThrowNew(self, mu):
        raise NotImplementedError()

    def _ExceptionOccurred(self, mu):
        raise NotImplementedError()

    def _ExceptionDescribe(self, mu):
        raise NotImplementedError()

    def _ExceptionClear(self, mu):
        raise NotImplementedError()

    def _FatalError(self, mu):
        raise NotImplementedError()

    def _PushLocalFrame(self, mu):
        raise NotImplementedError()

    def _PopLocalFrame(self, mu):
        raise NotImplementedError()

    def _NewGlobalRef(self, mu):
        raise NotImplementedError()

    def _DeleteGlobalRef(self, mu):
        raise NotImplementedError()

    def _DeleteLocalRef(self, mu):
        raise NotImplementedError()

    def _IsSameObject(self, mu):
        raise NotImplementedError()

    def _NewLocalRef(self, mu):
        raise NotImplementedError()

    def _EnsureLocalCapacity(self, mu):
        raise NotImplementedError()

    def _AllocObject(self, mu):
        raise NotImplementedError()

    def _NewObject(self, mu):
        raise NotImplementedError()

    def _NewObjectV(self, mu):
        raise NotImplementedError()

    def _NewObjectA(self, mu):
        raise NotImplementedError()

    def _GetObjectClass(self, mu):
        raise NotImplementedError()

    def _IsInstanceOf(self, mu):
        raise NotImplementedError()

    def _GetMethodID(self, mu):
        raise NotImplementedError()

    def _CallObjectMethod(self, mu):
        raise NotImplementedError()

    def _CallObjectMethodV(self, mu):
        raise NotImplementedError()

    def _CallObjectMethodA(self, mu):
        raise NotImplementedError()

    def _CallBooleanMethod(self, mu):
        raise NotImplementedError()

    def _CallBooleanMethodV(self, mu):
        raise NotImplementedError()

    def _CallBooleanMethodA(self, mu):
        raise NotImplementedError()

    def _CallByteMethod(self, mu):
        raise NotImplementedError()

    def _CallByteMethodV(self, mu):
        raise NotImplementedError()

    def _CallByteMethodA(self, mu):
        raise NotImplementedError()

    def _CallCharMethod(self, mu):
        raise NotImplementedError()

    def _CallCharMethodV(self, mu):
        raise NotImplementedError()

    def _CallCharMethodA(self, mu):
        raise NotImplementedError()

    def _CallShortMethod(self, mu):
        raise NotImplementedError()

    def _CallShortMethodV(self, mu):
        raise NotImplementedError()

    def _CallShortMethodA(self, mu):
        raise NotImplementedError()

    def _CallIntMethod(self, mu):
        raise NotImplementedError()

    def _CallIntMethodV(self, mu):
        raise NotImplementedError()

    def _CallIntMethodA(self, mu):
        raise NotImplementedError()

    def _CallLongMethod(self, mu):
        raise NotImplementedError()

    def _CallLongMethodV(self, mu):
        raise NotImplementedError()

    def _CallLongMethodA(self, mu):
        raise NotImplementedError()

    def _CallFloatMethod(self, mu):
        raise NotImplementedError()

    def _CallFloatMethodV(self, mu):
        raise NotImplementedError()

    def _CallFloatMethodA(self, mu):
        raise NotImplementedError()

    def _CallDoubleMethod(self, mu):
        raise NotImplementedError()

    def _CallDoubleMethodV(self, mu):
        raise NotImplementedError()

    def _CallDoubleMethodA(self, mu):
        raise NotImplementedError()

    def _CallVoidMethod(self, mu):
        raise NotImplementedError()

    def _CallVoidMethodV(self, mu):
        raise NotImplementedError()

    def _CallVoidMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualObjectMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualObjectMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualObjectMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualBooleanMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualBooleanMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualBooleanMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualByteMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualByteMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualByteMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualCharMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualCharMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualCharMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualShortMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualShortMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualShortMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualIntMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualIntMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualIntMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualLongMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualLongMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualLongMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualFloatMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualFloatMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualFloatMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualDoubleMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualDoubleMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualDoubleMethodA(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualVoidMethod(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualVoidMethodV(self, mu):
        raise NotImplementedError()

    def _CallNonvirtualVoidMethodA(self, mu):
        raise NotImplementedError()

    def _GetFieldID(self, mu):
        raise NotImplementedError()

    def _GetObjectField(self, mu):
        raise NotImplementedError()

    def _GetBooleanField(self, mu):
        raise NotImplementedError()

    def _GetByteField(self, mu):
        raise NotImplementedError()

    def _GetCharField(self, mu):
        raise NotImplementedError()

    def _GetShortField(self, mu):
        raise NotImplementedError()

    def _GetIntField(self, mu):
        raise NotImplementedError()

    def _GetLongField(self, mu):
        raise NotImplementedError()

    def _GetFloatField(self, mu):
        raise NotImplementedError()

    def _GetDoubleField(self, mu):
        raise NotImplementedError()

    def _SetObjectField(self, mu):
        raise NotImplementedError()

    def _SetBooleanField(self, mu):
        raise NotImplementedError()

    def _SetByteField(self, mu):
        raise NotImplementedError()

    def _SetCharField(self, mu):
        raise NotImplementedError()

    def _SetShortField(self, mu):
        raise NotImplementedError()

    def _SetIntField(self, mu):
        raise NotImplementedError()

    def _SetLongField(self, mu):
        raise NotImplementedError()

    def _SetFloatField(self, mu):
        raise NotImplementedError()

    def _SetDoubleField(self, mu):
        raise NotImplementedError()

    def _GetStaticMethodID(self, mu):
        raise NotImplementedError()

    def _CallStaticObjectMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticObjectMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticObjectMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticBooleanMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticBooleanMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticBooleanMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticByteMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticByteMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticByteMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticCharMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticCharMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticCharMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticShortMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticShortMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticShortMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticIntMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticIntMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticIntMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticLongMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticLongMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticLongMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticFloatMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticFloatMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticFloatMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticDoubleMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticDoubleMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticDoubleMethodA(self, mu):
        raise NotImplementedError()

    def _CallStaticVoidMethod(self, mu):
        raise NotImplementedError()

    def _CallStaticVoidMethodV(self, mu):
        raise NotImplementedError()

    def _CallStaticVoidMethodA(self, mu):
        raise NotImplementedError()

    def _GetStaticFieldID(self, mu):
        raise NotImplementedError()

    def _GetStaticObjectField(self, mu):
        raise NotImplementedError()

    def _GetStaticBooleanField(self, mu):
        raise NotImplementedError()

    def _GetStaticByteField(self, mu):
        raise NotImplementedError()

    def _GetStaticCharField(self, mu):
        raise NotImplementedError()

    def _GetStaticShortField(self, mu):
        raise NotImplementedError()

    def _GetStaticIntField(self, mu):
        raise NotImplementedError()

    def _GetStaticLongField(self, mu):
        raise NotImplementedError()

    def _GetStaticFloatField(self, mu):
        raise NotImplementedError()

    def _GetStaticDoubleField(self, mu):
        raise NotImplementedError()

    def _SetStaticObjectField(self, mu):
        raise NotImplementedError()

    def _SetStaticBooleanField(self, mu):
        raise NotImplementedError()

    def _SetStaticByteField(self, mu):
        raise NotImplementedError()

    def _SetStaticCharField(self, mu):
        raise NotImplementedError()

    def _SetStaticShortField(self, mu):
        raise NotImplementedError()

    def _SetStaticIntField(self, mu):
        raise NotImplementedError()

    def _SetStaticLongField(self, mu):
        raise NotImplementedError()

    def _SetStaticFloatField(self, mu):
        raise NotImplementedError()

    def _SetStaticDoubleField(self, mu):
        raise NotImplementedError()

    def _NewString(self, mu):
        raise NotImplementedError()

    def _GetStringLength(self, mu):
        raise NotImplementedError()

    def _GetStringChars(self, mu):
        raise NotImplementedError()

    def _ReleaseStringChars(self, mu):
        raise NotImplementedError()

    def _NewStringUTF(self, mu):
        raise NotImplementedError()

    def _GetStringUTFLength(self, mu):
        raise NotImplementedError()

    def _GetStringUTFChars(self, mu):
        raise NotImplementedError()

    def _ReleaseStringUTFChars(self, mu):
        raise NotImplementedError()

    def _GetArrayLength(self, mu):
        raise NotImplementedError()

    def _NewObjectArray(self, mu):
        raise NotImplementedError()

    def _GetObjectArrayElement(self, mu):
        raise NotImplementedError()

    def _SetObjectArrayElement(self, mu):
        raise NotImplementedError()

    def _NewBooleanArray(self, mu):
        raise NotImplementedError()

    def _NewByteArray(self, mu):
        raise NotImplementedError()

    def _NewCharArray(self, mu):
        raise NotImplementedError()

    def _NewShortArray(self, mu):
        raise NotImplementedError()

    def _NewIntArray(self, mu):
        raise NotImplementedError()

    def _NewLongArray(self, mu):
        raise NotImplementedError()

    def _NewFloatArray(self, mu):
        raise NotImplementedError()

    def _NewDoubleArray(self, mu):
        raise NotImplementedError()

    def _GetBooleanArrayElements(self, mu):
        raise NotImplementedError()

    def _GetByteArrayElements(self, mu):
        raise NotImplementedError()

    def _GetCharArrayElements(self, mu):
        raise NotImplementedError()

    def _GetShortArrayElements(self, mu):
        raise NotImplementedError()

    def _GetIntArrayElements(self, mu):
        raise NotImplementedError()

    def _GetLongArrayElements(self, mu):
        raise NotImplementedError()

    def _GetFloatArrayElements(self, mu):
        raise NotImplementedError()

    def _GetDoubleArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseBooleanArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseByteArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseCharArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseShortArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseIntArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseLongArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseFloatArrayElements(self, mu):
        raise NotImplementedError()

    def _ReleaseDoubleArrayElements(self, mu):
        raise NotImplementedError()

    def _GetBooleanArrayRegion(self, mu):
        raise NotImplementedError()

    def _GetByteArrayRegion(self, mu):
        raise NotImplementedError()

    def _GetCharArrayRegion(self, mu):
        raise NotImplementedError()

    def _GetShortArrayRegion(self, mu):
        raise NotImplementedError()

    def _GetIntArrayRegion(self, mu):
        raise NotImplementedError()

    def _GetLongArrayRegion(self, mu):
        raise NotImplementedError()

    def _GetFloatArrayRegion(self, mu):
        raise NotImplementedError()

    def _GetDoubleArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetBooleanArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetByteArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetCharArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetShortArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetIntArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetLongArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetFloatArrayRegion(self, mu):
        raise NotImplementedError()

    def _SetDoubleArrayRegion(self, mu):
        raise NotImplementedError()

    def _RegisterNatives(self, mu):
        raise NotImplementedError()

    def _UnregisterNatives(self, mu):
        raise NotImplementedError()

    def _MonitorEnter(self, mu):
        raise NotImplementedError()

    def _MonitorExit(self, mu):
        raise NotImplementedError()

    def _GetJavaVM(self, mu):
        vm = getPointerArg(mu, 1)
        mu.mem_write(vm, self.JavaVMAddr)
        return JNI_OK

    def _GetStringRegion(self, mu):
        raise NotImplementedError()

    def _GetStringUTFRegion(self, mu):
        raise NotImplementedError()

    def _GetPrimitiveArrayCritical(self, mu):
        raise NotImplementedError()

    def _ReleasePrimitiveArrayCritical(self, mu):
        raise NotImplementedError()

    def _GetStringCritical(self, mu):
        raise NotImplementedError()

    def _ReleaseStringCritical(self, mu):
        raise NotImplementedError()

    def _NewWeakGlobalRef(self, mu):
        raise NotImplementedError()

    def _DeleteWeakGlobalRef(self, mu):
        raise NotImplementedError()

    def _ExceptionCheck(self, mu):
        raise NotImplementedError()

    def _NewDirectByteBuffer(self, mu):
        raise NotImplementedError()

    def _GetDirectBufferAddress(self, mu):
        raise NotImplementedError()

    def _GetDirectBufferCapacity(self, mu):
        raise NotImplementedError()

    def _GetObjectRefType(self, mu):
        raise NotImplementedError()

    def getJniEnv(self):
        return self.JniEnvAddr

    def getJavaVM(self):
        return self.JavaVMAddr
