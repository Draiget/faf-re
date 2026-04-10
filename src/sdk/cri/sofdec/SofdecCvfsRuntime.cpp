// Extracted from SofdecRuntime.cpp for component-oriented maintenance.
// This file is included into SofdecRuntime.cpp and is not compiled as a standalone TU.

  extern "C" std::int32_t cvFsError_(const char* const message)
  {
    cvFsCallUsrErrFn(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&gCvFsErrorObject)), message);
    return 0;
  }

  /**
   * Address: 0x00B11DC0 (FUN_00B11DC0, _cvFsCallUsrErrFn)
   *
   * What it does:
   * Dispatches one CVFS error message to the registered user callback object.
   */
  void cvFsCallUsrErrFn(const std::int32_t errorObjectAddress, const char* const message)
  {
    (void)errorObjectAddress;
    if (cvfs_errfn != nullptr) {
      cvfs_errfn(cvfs_errobj, message);
    }
  }

  /**
   * Address: 0x00B12F70 (FUN_00B12F70, _cvFsEntryErrFunc)
   *
   * What it does:
   * Registers or clears the global CVFS user-error callback pair.
   */
  std::int32_t cvFsEntryErrFunc(const std::int32_t errorCallbackAddress, const std::int32_t errorObjectAddress)
  {
    if (errorCallbackAddress == 0) {
      cvfs_errfn = nullptr;
      cvfs_errobj = 0;
      return 0;
    }

    cvfs_errfn = reinterpret_cast<CvFsUserErrorBridgeFn>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(errorCallbackAddress))
    );
    cvfs_errobj = errorObjectAddress;
    return errorObjectAddress;
  }

  /**
   * Address: 0x00B11E00 (FUN_00B11E00, _cvFsInit)
   *
   * What it does:
   * Initializes CVFS runtime pools on first init call and increments init count.
   */
  const char* cvFsInit()
  {
    const char* result = kCvFsVersionString;
    if (cvfs_init_cnt == 0) {
      for (CvFsHandleView& handle : gCvFsHandlePool) {
        handle.interfaceView = nullptr;
        handle.handleAddress = 0;
      }

      for (CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
        deviceSlot.deviceName[0] = '\0';
      }

      std::memset(gCvFsDefaultDeviceName.data(), 0, gCvFsDefaultDeviceName.size());
    }

    ++cvfs_init_cnt;
    return result;
  }

  /**
   * Address: 0x00B11E60 (FUN_00B11E60, _cvFsFinish)
   *
   * What it does:
   * Decrements CVFS init count and on last user closes active handles then clears
   * handle/device/default-device lanes.
   */
  void cvFsFinish()
  {
    --cvfs_init_cnt;
    if (cvfs_init_cnt != 0) {
      return;
    }

    for (CvFsHandleView& handle : gCvFsHandlePool) {
      if (handle.interfaceView != nullptr) {
        handle.interfaceView->closeFile(handle.handleAddress);
      }
      handle.interfaceView = nullptr;
      handle.handleAddress = 0;
    }

    for (CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      deviceSlot.deviceName[0] = '\0';
    }

    std::memset(gCvFsDefaultDeviceName.data(), 0, gCvFsDefaultDeviceName.size());
  }

  /**
   * Address: 0x00B12F30 (FUN_00B12F30, _cvFsGetDevName)
   *
   * What it does:
   * Returns the registered CVFS device name for one opened handle.
   */
  const char* cvFsGetDevName(const CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetDevNameVtable);
      return nullptr;
    }

    for (const CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      if (deviceSlot.interfaceView == handle->interfaceView) {
        return deviceSlot.deviceName.data();
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B12FA0 (FUN_00B12FA0, _cvFsOptFn1)
   *
   * What it does:
   * Dispatches one option packet through CVFS option bridge slot #1.
   */
  std::int32_t cvFsOptFn1(
    CvFsHandleView* const handle,
    const std::int32_t optionCode,
    const std::int32_t optionArg0,
    const std::int32_t optionArg1
  )
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrOptFn1Handle);
      return 0;
    }

    const CvFsDeviceOptionFn optionBridge = handle->interfaceView->option;
    if (optionBridge == nullptr) {
      (void)cvFsError_(kCvFsErrOptFn1Vtable);
      return 0;
    }

    return optionBridge(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handle->handleAddress))),
      optionCode,
      optionArg0,
      optionArg1
    );
  }

  /**
   * Address: 0x00B13000 (FUN_00B13000, _cvFsOptFn2)
   *
   * What it does:
   * Dispatches one option packet through CVFS option bridge slot #2.
   */
  std::int32_t cvFsOptFn2(
    CvFsHandleView* const handle,
    const std::int32_t optionCode,
    const std::int32_t optionArg0,
    const std::int32_t optionArg1
  )
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrOptFn2Handle);
      return 0;
    }

    const CvFsDeviceOptionFn optionBridge = handle->interfaceView->option2;
    if (optionBridge == nullptr) {
      (void)cvFsError_(kCvFsErrOptFn2Vtable);
      return 0;
    }

    return optionBridge(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handle->handleAddress))),
      optionCode,
      optionArg0,
      optionArg1
    );
  }

  /**
   * Address: 0x00B12CC0 (FUN_00B12CC0, _cvFsGetMaxByteRate)
   *
   * What it does:
   * Returns max byte-rate capability from one opened CVFS handle.
   */
  std::int32_t cvFsGetMaxByteRate(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetMaxByteRateHandle);
      return 0;
    }

    const CvFsGetMaxByteRateFn getMaxByteRateBridge = handle->interfaceView->getMaxByteRate;
    if (getMaxByteRateBridge == nullptr) {
      (void)cvFsError_(kCvFsErrGetMaxByteRateVtable);
      return 0;
    }

    return getMaxByteRateBridge(handle->handleAddress);
  }

  /**
   * Address: 0x00B12D00 (FUN_00B12D00, _cvFsMakeDir)
   *
   * What it does:
   * Creates one directory through the resolved CVFS device bridge.
   */
  std::int32_t cvFsMakeDir(char* const fileName)
  {
    if (fileName == nullptr) {
      (void)cvFsError_(kCvFsErrMakeDirInvalidDirectory);
      return -1;
    }

    char filePath[300]{};
    char deviceName[300]{};
    getDevName(deviceName, filePath, fileName);
    if (filePath[0] == '\0') {
      (void)cvFsError_(kCvFsErrMakeDirInvalidDirectory);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, fileName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrMakeDirDeviceNotFound);
      return -1;
    }

    const CvFsPathOperationFn makeDirBridge = deviceInterface->makeDir;
    if (makeDirBridge == nullptr) {
      (void)cvFsError_(kCvFsErrMakeDirVtable);
      return -1;
    }

    return makeDirBridge(filePath);
  }

  /**
   * Address: 0x00B12DB0 (FUN_00B12DB0, _cvFsRemoveDir)
   *
   * What it does:
   * Removes one directory through the resolved CVFS device bridge.
   */
  std::int32_t cvFsRemoveDir(char* const fileName)
  {
    if (fileName == nullptr) {
      (void)cvFsError_(kCvFsErrRemoveDirInvalidDirectory);
      return -1;
    }

    char filePath[300]{};
    char deviceName[300]{};
    getDevName(deviceName, filePath, fileName);
    if (filePath[0] == '\0') {
      (void)cvFsError_(kCvFsErrRemoveDirInvalidDirectory);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, fileName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrRemoveDirDeviceNotFound);
      return -1;
    }

    const CvFsPathOperationFn removeDirBridge = deviceInterface->removeDir;
    if (removeDirBridge == nullptr) {
      (void)cvFsError_(kCvFsErrRemoveDirVtable);
      return -1;
    }

    return removeDirBridge(filePath);
  }

  /**
   * Address: 0x00B12E70 (FUN_00B12E70, _cvFsDeleteFile)
   *
   * What it does:
   * Deletes one file path through the resolved CVFS device bridge.
   */
  std::int32_t cvFsDeleteFile(char* const fileName)
  {
    if (fileName == nullptr) {
      (void)cvFsError_(kCvFsErrDeleteFileInvalidFileName);
      return -1;
    }

    char filePath[300]{};
    char deviceName[300]{};
    getDevName(deviceName, filePath, fileName);
    if (filePath[0] == '\0') {
      (void)cvFsError_(kCvFsErrDeleteFileInvalidFileName);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, fileName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrDeleteFileDeviceNotFound);
      return -1;
    }

    const CvFsPathOperationFn deleteFileBridge = deviceInterface->deleteFile;
    if (deleteFileBridge == nullptr) {
      (void)cvFsError_(kCvFsErrDeleteFileVtable);
      return -1;
    }

    return deleteFileBridge(filePath);
  }

  /**
   * Address: 0x00B12330 (FUN_00B12330, _releaseCvFsHn)
   *
   * What it does:
   * Clears one CVFS handle lane (`interface`, `handleAddress`) and returns the
   * original handle pointer.
   */
  extern "C" CvFsHandleView* releaseCvFsHn(CvFsHandleView* const handle)
  {
    handle->handleAddress = 0;
    handle->interfaceView = nullptr;
    return handle;
  }

  /**
   * Address: 0x00B12440 (FUN_00B12440, _cvFsClose)
   *
   * What it does:
   * Validates one CVFS handle lane, invokes vtable close callback when
   * available, and releases the handle bookkeeping.
   */
  extern "C" std::int32_t cvFsClose(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      return cvFsError_(kCvFsErrCloseHandle);
    }

    if (handle->interfaceView == nullptr) {
      return cvFsError_(kCvFsErrCloseVtable);
    }

    CvFsCloseBridgeFn const closeBridge = handle->interfaceView->closeFile;
    if (closeBridge == nullptr) {
      return cvFsError_(kCvFsErrCloseVtable);
    }

    closeBridge(handle->handleAddress);
    return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(releaseCvFsHn(handle)));
  }

  /**
   * Address: 0x00B12150 (FUN_00B12150, _cvFsGetDefDev)
   *
   * What it does:
   * Returns the pointer to the active default CVFS device name lane.
   */
  extern "C" char* cvFsGetDefDev()
  {
    return gCvFsDefaultDeviceName.data();
  }

  /**
   * Address: 0x00B12480 (FUN_00B12480, _cvFsTell)
   *
   * What it does:
   * Returns current stream position for one CVFS handle.
   */
  extern "C" std::int32_t cvFsTell(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrTellHandle);
      return 0;
    }

    CvFsHandleOperationFn const tellBridge = handle->interfaceView->tellPosition;
    if (tellBridge == nullptr) {
      (void)cvFsError_(kCvFsErrTellVtable);
      return 0;
    }

    return tellBridge(handle->handleAddress);
  }

  /**
   * Address: 0x00B12520 (FUN_00B12520, _cvFsReqRd)
   *
   * What it does:
   * Queues one read request for the selected CVFS stream handle.
   */
  extern "C" std::int32_t cvFsReqRd(
    CvFsHandleView* const handle,
    const std::int32_t bufferAddress,
    const std::int32_t byteCount
  )
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrReqRdHandle);
      return 0;
    }

    CvFsHandleReadWriteFn const requestReadBridge = handle->interfaceView->requestRead;
    if (requestReadBridge == nullptr) {
      (void)cvFsError_(kCvFsErrReqRdVtable);
      return 0;
    }

    return requestReadBridge(handle->handleAddress, bufferAddress, byteCount);
  }

  /**
   * Address: 0x00B12570 (FUN_00B12570, _cvFsReqWr)
   *
   * What it does:
   * Queues one write request for the selected CVFS stream handle.
   */
  extern "C" std::int32_t cvFsReqWr(
    CvFsHandleView* const handle,
    const std::int32_t bufferAddress,
    const std::int32_t byteCount
  )
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrReqWrHandle);
      return 0;
    }

    CvFsHandleReadWriteFn const requestWriteBridge = handle->interfaceView->requestWrite;
    if (requestWriteBridge == nullptr) {
      (void)cvFsError_(kCvFsErrReqWrVtable);
      return 0;
    }

    return requestWriteBridge(handle->handleAddress, bufferAddress, byteCount);
  }

  /**
   * Address: 0x00B125C0 (FUN_00B125C0, _cvFsStopTr)
   *
   * What it does:
   * Requests transfer stop for one opened CVFS stream handle.
   */
  extern "C" std::int32_t cvFsStopTr(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      return cvFsError_(kCvFsErrStopTrHandle);
    }

    CvFsHandleOperationFn const stopTransferBridge = handle->interfaceView->stopTransfer;
    if (stopTransferBridge == nullptr) {
      return cvFsError_(kCvFsErrStopTrVtable);
    }

    return stopTransferBridge(handle->handleAddress);
  }

  /**
   * Address: 0x00B12600 (FUN_00B12600, _cvFsExecServer)
   *
   * What it does:
   * Executes one server tick across registered CVFS devices.
   */
  extern "C" void cvFsExecServer()
  {
    for (const CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      CvFsDeviceInterfaceView* const deviceInterface = deviceSlot.interfaceView;
      if (deviceInterface == nullptr) {
        continue;
      }

      CvFsNoArgOperationFn const execServerBridge = deviceInterface->execServer;
      if (execServerBridge != nullptr) {
        (void)execServerBridge();
      }
    }
  }

  /**
   * Address: 0x00B12680 (FUN_00B12680, _cvFsGetFileSize)
   *
   * What it does:
   * Resolves one file path and queries file size through device slot +0x08.
   */
  extern "C" std::int32_t cvFsGetFileSize(char* const fileName)
  {
    if (fileName == nullptr) {
      (void)cvFsError_(kCvFsErrGetFileSizeIllegalFileName);
      return 0;
    }

    char filePath[kCvFsPathScratchBytes]{};
    char deviceName[kCvFsPathScratchBytes]{};
    getDevName(deviceName, filePath, fileName);
    if (filePath[0] == '\0') {
      (void)cvFsError_(kCvFsErrGetFileSizeIllegalFileName);
      return 0;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, fileName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrGetFileSizeDeviceNotFound);
      return 0;
    }

    CvFsPathOperationFn const getFileSizeBridge = deviceInterface->getFileSize;
    if (getFileSizeBridge == nullptr) {
      (void)cvFsError_(kCvFsErrGetFileSizeVtable);
      return 0;
    }

    return getFileSizeBridge(filePath);
  }

  /**
   * Address: 0x00B12740 (FUN_00B12740, _cvFsGetFileSizeEx)
   *
   * What it does:
   * Resolves one file path and queries file size through device slot +0x5C.
   */
  extern "C" std::int32_t cvFsGetFileSizeEx(char* const fileName, const std::int32_t optionArg)
  {
    if (fileName == nullptr) {
      (void)cvFsError_(kCvFsErrGetFileSizeExIllegalFileName);
      return 0;
    }

    char filePath[kCvFsPathScratchBytes]{};
    char deviceName[kCvFsPathScratchBytes]{};
    getDevName(deviceName, filePath, fileName);
    if (filePath[0] == '\0') {
      (void)cvFsError_(kCvFsErrGetFileSizeExIllegalFileName);
      return 0;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, fileName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrGetFileSizeExDeviceNotFound);
      return 0;
    }

    CvFsPathArgOperationFn const getFileSizeExBridge = deviceInterface->getFileSizeEx;
    if (getFileSizeExBridge == nullptr) {
      (void)cvFsError_(kCvFsErrGetFileSizeExVtable);
      return 0;
    }

    return getFileSizeExBridge(filePath, optionArg);
  }

  /**
   * Address: 0x00B12800 (FUN_00B12800, _cvFsGetFileSizeByHndl)
   *
   * What it does:
   * Returns stream file size via option lane `300` for one opened CVFS handle.
   */
  extern "C" std::int32_t cvFsGetFileSizeByHndl(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetFileSizeByHandleIllegalHandle);
      return -1;
    }

    constexpr std::int32_t kCvFsOptionGetFileSizeByHandle = 300;
    constexpr std::int32_t kCvFsFileSizeUnknown = 0x7FFFFFFF;
    CvFsDeviceOptionFn const optionBridge = handle->interfaceView->option;
    if (optionBridge == nullptr) {
      return kCvFsFileSizeUnknown;
    }

    return optionBridge(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handle->handleAddress))),
      kCvFsOptionGetFileSizeByHandle,
      0,
      0
    );
  }

  /**
   * Address: 0x00B124D0 (FUN_00B124D0, _cvFsSeek)
   *
   * What it does:
   * Validates one CVFS handle lane and dispatches one seek request through the
   * device seek bridge.
   */
  extern "C" std::int32_t cvFsSeek(
    CvFsHandleView* const handle,
    const std::int32_t seekOffset,
    const std::int32_t seekOrigin
  )
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrSeekHandle);
      return 0;
    }

    CvFsSeekBridgeFn const seekBridge = handle->interfaceView->seekFile;
    if (seekBridge == nullptr) {
      (void)cvFsError_(kCvFsErrSeekVtable);
      return 0;
    }

    return seekBridge(handle->handleAddress, seekOffset, seekOrigin);
  }

  /**
   * Address: 0x00B12630 (FUN_00B12630, _cvFsGetStat)
   *
   * What it does:
   * Validates one CVFS handle lane and queries the current stream status from
   * the device status bridge.
   */
  extern "C" std::int32_t cvFsGetStat(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetStatHandle);
      return 3;
    }

    CvFsGetStatBridgeFn const getStatBridge = handle->interfaceView->getStat;
    if (getStatBridge == nullptr) {
      (void)cvFsError_(kCvFsErrGetStatVtable);
      return 3;
    }

    return getStatBridge(handle->handleAddress);
  }

  /**
   * Address: 0x00B12840 (FUN_00B12840, _cvFsGetFreeSize)
   *
   * What it does:
   * Resolves one CVFS device lane and queries free-size through the device
   * interface free-size callback slot.
   */
  extern "C" std::int32_t cvFsGetFreeSize(const char* const deviceName)
  {
    std::int32_t freeSize = 0;
    char resolvedDeviceName[kCvFsPathScratchBytes]{};

    if (deviceName != nullptr && deviceName[0] != '\0') {
      std::strcpy(resolvedDeviceName, deviceName);
    } else {
      (void)getDefDev(resolvedDeviceName);
      if (resolvedDeviceName[0] == '\0') {
        (void)cvFsError_(kCvFsErrGetFreeSizeDeviceNotFound);
        return 0;
      }
    }

    const std::size_t compareLength = std::strlen(resolvedDeviceName);
    if (compareLength == 0u) {
      (void)cvFsError_(kCvFsErrGetFreeSizeDeviceNotFound);
      return 0;
    }

    for (const CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      if (std::strncmp(resolvedDeviceName, deviceSlot.deviceName.data(), compareLength) != 0) {
        continue;
      }

      if (deviceSlot.interfaceView == nullptr) {
        (void)cvFsError_(kCvFsErrGetFreeSizeVtable);
        return 0;
      }

      CvFsNoArgOperationFn const getFreeSizeBridge = deviceSlot.interfaceView->getFreeSize;
      if (getFreeSizeBridge != nullptr) {
        freeSize = getFreeSizeBridge();
      }
    }

    return freeSize;
  }

  /**
   * Address: 0x00B12930 (FUN_00B12930, _cvFsGetSctLen)
   *
   * What it does:
   * Queries device sector-length lane for one opened CVFS handle.
   */
  extern "C" std::int32_t cvFsGetSctLen(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetSctLenHandle);
      return 0;
    }

    CvFsHandleOperationFn const getSectorLengthBridge = handle->interfaceView->getSectorLength;
    if (getSectorLengthBridge == nullptr) {
      (void)cvFsError_(kCvFsErrGetSctLenVtable);
      return 0;
    }

    return getSectorLengthBridge(handle->handleAddress);
  }

  /**
   * Address: 0x00B12980 (FUN_00B12980, _cvFsSetSctLen)
   *
   * What it does:
   * Dispatches one sector-length update request for an opened CVFS handle.
   */
  extern "C" std::int32_t cvFsSetSctLen(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      return cvFsError_(kCvFsErrSetSctLenHandle);
    }

    CvFsHandleOperationFn const setSectorLengthBridge = handle->interfaceView->setSectorLength;
    if (setSectorLengthBridge == nullptr) {
      return cvFsError_(kCvFsErrSetSctLenVtable);
    }

    return setSectorLengthBridge(handle->handleAddress);
  }

  /**
   * Address: 0x00B129C0 (FUN_00B129C0, _cvFsGetNumTr)
   *
   * What it does:
   * Queries transfer-count lane for one opened CVFS handle.
   */
  extern "C" std::int32_t cvFsGetNumTr(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetNumTrHandle);
      return 0;
    }

    CvFsHandleOperationFn const getTransferCountBridge = handle->interfaceView->getTransferCount;
    if (getTransferCountBridge == nullptr) {
      (void)cvFsError_(kCvFsErrGetNumTrVtable);
      return 0;
    }

    return getTransferCountBridge(handle->handleAddress);
  }

  /**
   * Address: 0x00B12A10 (FUN_00B12A10, _cvFsChangeDir)
   *
   * What it does:
   * Resolves device/path lanes for one directory and dispatches change-dir
   * through the selected CVFS device.
   */
  extern "C" std::int32_t cvFsChangeDir(char* const directoryName)
  {
    if (directoryName == nullptr) {
      (void)cvFsError_(kCvFsErrChangeDirInvalidDirectory);
      return -1;
    }

    char filePath[kCvFsPathScratchBytes]{};
    char deviceName[kCvFsPathScratchBytes]{};
    getDevName(deviceName, filePath, directoryName);
    if (filePath[0] == '\0') {
      (void)cvFsError_(kCvFsErrChangeDirInvalidDirectory);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, directoryName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrChangeDirDeviceNotFound);
      return -1;
    }

    CvFsPathOperationFn const changeDirBridge = deviceInterface->changeDir;
    if (changeDirBridge == nullptr) {
      (void)cvFsError_(kCvFsErrChangeDirVtable);
      return -1;
    }

    return changeDirBridge(filePath);
  }

  /**
   * Address: 0x00B12AD0 (FUN_00B12AD0, _cvFsIsExistFile)
   *
   * What it does:
   * Resolves device/path lanes for one file and returns file-exists status.
   */
  extern "C" std::int32_t cvFsIsExistFile(char* const fileName)
  {
    char filePath[kCvFsPathScratchBytes]{};
    char deviceName[kCvFsPathScratchBytes]{};
    getDevName(deviceName, filePath, fileName);
    if (filePath[0] == '\0') {
      (void)cvFsError_(kCvFsErrIsExistFileInvalidFileName);
      return 0;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, fileName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrIsExistFileDeviceNotFound);
      return 0;
    }

    CvFsPathOperationFn const isFileExistsBridge = deviceInterface->isFileExists;
    if (isFileExistsBridge == nullptr) {
      (void)cvFsError_(kCvFsErrIsExistFileVtable);
      return 0;
    }

    return isFileExistsBridge(filePath);
  }

  /**
   * Address: 0x00B12B70 (FUN_00B12B70, _cvFsGetNumFiles)
   *
   * What it does:
   * Queries file-count lane for one device; uses option bridge when the device
   * requires explicit prefixed paths.
   */
  extern "C" std::int32_t cvFsGetNumFiles(char* const deviceName)
  {
    const std::size_t compareLength = std::strlen(deviceName);
    for (const CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      if (std::strncmp(deviceName, deviceSlot.deviceName.data(), compareLength) != 0) {
        continue;
      }

      CvFsDeviceInterfaceView* const deviceInterface = deviceSlot.interfaceView;
      if (isNeedDevName(deviceName) != 0) {
        if (deviceInterface != nullptr) {
          CvFsDeviceOptionFn const optionBridge = deviceInterface->option;
          if (optionBridge != nullptr) {
            std::int32_t optionBuffer = 0;
            return optionBridge(&optionBuffer, 4, 0, 0);
          }
        }
      } else if (deviceInterface != nullptr) {
        CvFsNoArgOperationFn const getNumFilesBridge = deviceInterface->getNumFiles;
        if (getNumFilesBridge != nullptr) {
          return getNumFilesBridge();
        }
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B12C10 (FUN_00B12C10, _cvFsLoadDirInfo)
   *
   * What it does:
   * Resolves device lanes for one path and dispatches directory-info load
   * through the device callback at interface slot +0x48.
   */
  extern "C" std::int32_t cvFsLoadDirInfo(
    char* const fileName,
    const std::int32_t optionArg0,
    const std::int32_t optionArg1
  )
  {
    char deviceName[kCvFsPathScratchBytes]{};
    char filePath[kCvFsPathScratchBytes]{};
    getDevName(deviceName, filePath, fileName);

    if (deviceName[0] == '\0') {
      (void)getDefDev(deviceName);
      if (deviceName[0] == '\0') {
        (void)cvFsError_(kCvFsErrIsExistFileIllegalDeviceName);
        return 0;
      }
    }

    (void)addDevName(deviceName, filePath);
    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      return 0;
    }

    CvFsLoadDirInfoFn const loadDirInfoBridge = deviceInterface->loadDirInfo;
    if (loadDirInfoBridge == nullptr) {
      return 0;
    }

    return loadDirInfoBridge(fileName, optionArg0, optionArg1);
  }

  /**
   * Address: 0x00B13600 (FUN_00B13600, _cvFsGetFsys64Info)
   *
   * What it does:
   * Dispatches CVFS option code `299` to query 64-bit filesystem info lane.
   */
  extern "C" std::int32_t cvFsGetFsys64Info(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetFsys64InfoHandle);
      return 0;
    }

    CvFsDeviceOptionFn const optionBridge = handle->interfaceView->option;
    if (optionBridge == nullptr) {
      return 0;
    }

    return optionBridge(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handle->handleAddress))),
      299,
      0,
      0
    );
  }

  /**
   * Address: 0x00B13060 (FUN_00B13060, _cvFsSetCurVolume)
   *
   * What it does:
   * Sends default/current volume selection packet to one CVFS device.
   */
  extern "C" std::int32_t cvFsSetCurVolume(char* const deviceName, const std::int32_t volumeName)
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrSetCurVolumeInvalidDeviceName);
      return -1;
    }
    if (volumeName == 0) {
      (void)cvFsError_(kCvFsErrSetCurVolumeInvalidVolumeName);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrSetCurVolumeDeviceNotFound);
      return -1;
    }

    std::int32_t optionValues[5]{};
    optionValues[0] = volumeName;
    CvFsDeviceOptionFn const optionBridge = deviceInterface->option;
    if (optionBridge == nullptr) {
      return -1;
    }

    return optionBridge(optionValues, 1, 0, 0);
  }

  /**
   * Address: 0x00B13110 (FUN_00B13110, _cvFsAddVolumeEx)
   *
   * What it does:
   * Sends one extended add-volume option packet to the selected CVFS device.
   */
  extern "C" std::int32_t cvFsAddVolumeEx(
    char* const deviceName,
    const std::int32_t volumeName,
    const std::int32_t imageHandleAddress,
    const std::int32_t modeOrFlags
  )
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrAddVolumeExInvalidDeviceName);
      return -1;
    }
    if (volumeName == 0) {
      (void)cvFsError_(kCvFsErrAddVolumeExInvalidVolumeName);
      return -1;
    }
    if (imageHandleAddress == 0) {
      (void)cvFsError_(kCvFsErrAddVolumeExInvalidImageHandle);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrAddVolumeExDeviceNotFound);
      return -1;
    }

    std::int32_t optionValues[5]{};
    optionValues[0] = imageHandleAddress;
    optionValues[1] = volumeName;
    optionValues[2] = modeOrFlags;

    CvFsDeviceOptionFn const optionBridge = deviceInterface->option;
    if (optionBridge == nullptr) {
      return -1;
    }

    return optionBridge(optionValues, 2, 0, 0);
  }

  /**
   * Address: 0x00B131E0 (FUN_00B131E0, _cvFsDelVolume)
   *
   * What it does:
   * Sends one delete-volume option packet to the selected CVFS device.
   */
  extern "C" std::int32_t cvFsDelVolume(char* const deviceName, const std::int32_t volumeName)
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrDelVolumeInvalidDeviceName);
      return -1;
    }
    if (volumeName == 0) {
      (void)cvFsError_(kCvFsErrDelVolumeInvalidVolumeName);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrDelVolumeDeviceNotFound);
      return -1;
    }

    std::int32_t optionValues[5]{};
    optionValues[1] = volumeName;

    CvFsDeviceOptionFn const optionBridge = deviceInterface->option;
    if (optionBridge == nullptr) {
      return -1;
    }

    return optionBridge(optionValues, 3, 0, 0);
  }

  /**
   * Address: 0x00B13280 (FUN_00B13280, _cvFsGetVolumeInfo)
   *
   * What it does:
   * Sends one get-volume-info option packet to the selected CVFS device.
   */
  extern "C" std::int32_t cvFsGetVolumeInfo(
    char* const deviceName,
    const std::int32_t volumeName,
    const std::int32_t infoCode
  )
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrGetVolumeInfoInvalidDeviceName);
      return -1;
    }
    if (volumeName == 0) {
      (void)cvFsError_(kCvFsErrGetVolumeInfoInvalidVolumeName);
      return -1;
    }

    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrGetVolumeInfoDeviceNotFound);
      return -1;
    }

    std::int32_t optionValues[5]{};
    optionValues[1] = volumeName;
    optionValues[2] = infoCode;

    CvFsDeviceOptionFn const optionBridge = deviceInterface->option;
    if (optionBridge == nullptr) {
      return -1;
    }

    return optionBridge(optionValues, 5, 0, 0);
  }

  /**
   * Address: 0x00B13430 (FUN_00B13430, _cvFsIsExistDevice)
   *
   * What it does:
   * Returns whether one device-name prefix is registered in CVFS.
   */
  extern "C" BOOL cvFsIsExistDevice(char* const deviceName)
  {
    return (getDevice(deviceName) != nullptr) ? TRUE : FALSE;
  }

  /**
   * Address: 0x00B13450 (FUN_00B13450, _cvFsGetNumTr64)
   *
   * What it does:
   * Queries and combines high/low 32-bit transfer-count option lanes.
   */
  extern "C" std::uint64_t cvFsGetNumTr64(CvFsHandleView* const handle)
  {
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrGetNumTr64Handle);
      return 0;
    }

    CvFsDeviceOptionFn const optionBridge = handle->interfaceView->option;
    if (optionBridge == nullptr) {
      return 0;
    }

    const std::int32_t handleAddress = handle->handleAddress;
    const void* const optionContext
      = reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handleAddress)));

    const std::uint32_t highPart = static_cast<std::uint32_t>(optionBridge(const_cast<void*>(optionContext), 200, 0, 0));
    const std::uint32_t lowPart = static_cast<std::uint32_t>(optionBridge(const_cast<void*>(optionContext), 201, 0, 0));
    return (static_cast<std::uint64_t>(highPart) << 32) | static_cast<std::uint64_t>(lowPart);
  }

  /**
   * Address: 0x00B134C0 (FUN_00B134C0, _cvFsGetFileSize64)
   *
   * What it does:
   * Resolves device/path context and combines 64-bit file-size option lanes.
   */
  extern "C" std::uint64_t cvFsGetFileSize64(char* const fileName)
  {
    char filePath[300]{};
    char deviceName[300]{};
    getDevName(deviceName, filePath, fileName);

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceName, filePath, fileName);
    CvFsDeviceOptionFn const optionBridge = deviceInterface->option;
    if (optionBridge == nullptr) {
      return 0;
    }

    const std::int32_t pathAddress
      = static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(filePath)));
    const std::uint32_t highPart
      = static_cast<std::uint32_t>(optionBridge(fileName, 202, pathAddress, 0));
    const std::uint32_t lowPart
      = static_cast<std::uint32_t>(optionBridge(fileName, 203, pathAddress, 0));
    return (static_cast<std::uint64_t>(highPart) << 32) | static_cast<std::uint64_t>(lowPart);
  }

  /**
   * Address: 0x00B13560 (FUN_00B13560, _cvFsGetFileSizeEx64)
   *
   * What it does:
   * Queries extended 64-bit size option lanes (`204`/`205`) for one file path.
   */
  extern "C" std::uint64_t cvFsGetFileSizeEx64(char* const fileName, const std::int32_t optionArg)
  {
    char filePath[300]{};
    char deviceName[300];

    // Preserve original lane order from binary: probe device before parsing.
    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      return 0;
    }

    getDevName(deviceName, filePath, fileName);

    CvFsDeviceOptionFn const optionBridge = deviceInterface->option;
    if (optionBridge == nullptr) {
      return 0;
    }

    const std::int32_t pathAddress
      = static_cast<std::int32_t>(static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(filePath)));
    const std::uint32_t highPart
      = static_cast<std::uint32_t>(optionBridge(fileName, 204, pathAddress, optionArg));
    const std::uint32_t lowPart
      = static_cast<std::uint32_t>(optionBridge(fileName, 205, pathAddress, optionArg));
    return (static_cast<std::uint64_t>(highPart) << 32) | static_cast<std::uint64_t>(lowPart);
  }

  /**
   * Address: 0x00B120A0 (FUN_00B120A0, _cvFsSetDefDev)
   *
   * What it does:
   * Validates one default CVFS device lane, uppercases it, and stores it as
   * active default when registered.
   */
  extern "C" std::int32_t cvFsSetDefDev(const char* const deviceName)
  {
    if (deviceName == nullptr) {
      return cvFsError_(kCvFsErrSetDefDevInvalidDeviceName);
    }

    const std::size_t nameLength = std::strlen(deviceName);
    if (nameLength == 0u) {
      gCvFsDefaultDeviceName[0] = '\0';
      return 0;
    }

    std::array<char, kCvFsPathScratchBytes> upperName{};
    std::strncpy(upperName.data(), deviceName, upperName.size() - 1u);
    (void)toUpperStr(upperName.data());

    if (isExistDev(upperName.data(), nameLength) != 1) {
      return cvFsError_(kCvFsErrSetDefDevUnknownDeviceName);
    }

    std::memset(gCvFsDefaultDeviceName.data(), 0, gCvFsDefaultDeviceName.size());
    const std::size_t bytesToCopy = (nameLength + 1u < gCvFsDefaultDeviceName.size())
      ? (nameLength + 1u)
      : gCvFsDefaultDeviceName.size();
    std::memcpy(gCvFsDefaultDeviceName.data(), upperName.data(), bytesToCopy);
    return static_cast<std::int32_t>(nameLength + 1u);
  }

  /**
   * Address: 0x00B11FB0 (FUN_00B11FB0, _getDevice)
   *
   * What it does:
   * Returns the CVFS interface lane for one device-name prefix match.
   */
  CvFsDeviceInterfaceView* getDevice(const char* const deviceName)
  {
    if (deviceName == nullptr) {
      return nullptr;
    }

    const std::size_t compareLength = std::strlen(deviceName);
    for (CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      if (std::strncmp(deviceName, deviceSlot.deviceName.data(), compareLength) == 0) {
        return deviceSlot.interfaceView;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B11F40 (FUN_00B11F40, _addDevice)
   *
   * What it does:
   * Adds one device-interface lane to the fixed CVFS device table when absent.
   */
  CvFsDeviceInterfaceView* addDevice(const char* const deviceName, void* (__cdecl* const deviceFactory)())
  {
    std::array<char, kCvFsDeviceNameBytes> upperDeviceName{};
    if (deviceName != nullptr) {
      std::strncpy(upperDeviceName.data(), deviceName, upperDeviceName.size() - 1u);
    }
    (void)toUpperStr(upperDeviceName.data());

    auto* const deviceInterface = reinterpret_cast<CvFsDeviceInterfaceView*>(deviceFactory());
    if (getDevice(upperDeviceName.data()) != nullptr) {
      return deviceInterface;
    }

    std::size_t freeSlotIndex = 0;
    for (; freeSlotIndex < gCvFsDeviceSlots.size(); ++freeSlotIndex) {
      if (gCvFsDeviceSlots[freeSlotIndex].deviceName[0] == '\0') {
        break;
      }
    }

    if (freeSlotIndex == gCvFsDeviceSlots.size()) {
      return nullptr;
    }

    gCvFsDeviceSlots[freeSlotIndex].interfaceView = deviceInterface;
    std::strcpy(gCvFsDeviceSlots[freeSlotIndex].deviceName.data(), upperDeviceName.data());
    return deviceInterface;
  }

  /**
   * Address: 0x00B12040 (FUN_00B12040, _cvFsDelDev)
   *
   * What it does:
   * Clears one device slot by matching the requested CVFS device prefix.
   */
  std::int32_t cvFsDelDev(const char* const deviceName)
  {
    if (deviceName == nullptr) {
      return cvFsError_(kCvFsErrDelDevInvalidDeviceName);
    }

    const std::size_t compareLength = std::strlen(deviceName);
    std::int32_t compareResult = 1;
    for (CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      compareResult = std::strncmp(deviceName, deviceSlot.deviceName.data(), compareLength);
      if (compareResult == 0) {
        deviceSlot.deviceName[0] = '\0';
        return compareResult;
      }
    }
    return compareResult;
  }

  /**
   * Address: 0x00B12300 (FUN_00B12300, _allocCvFsHn)
   *
   * What it does:
   * Returns one free CVFS handle from the fixed handle pool.
   */
  CvFsHandleView* allocCvFsHn()
  {
    for (CvFsHandleView& handle : gCvFsHandlePool) {
      if (handle.handleAddress == 0) {
        return &handle;
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B12350 (FUN_00B12350, _getDevName)
   *
   * What it does:
   * Splits `DEV:path` into uppercase device prefix + path buffer.
   */
  void getDevName(char* const outDeviceName, char* const outFilePath, const char* const fileName)
  {
    if (fileName == nullptr) {
      return;
    }

    std::int32_t splitIndex = 0;
    while (splitIndex < 297) {
      const char symbol = fileName[splitIndex];
      if (symbol == ':' || symbol == '\0') {
        break;
      }
      outDeviceName[splitIndex] = symbol;
      ++splitIndex;
    }

    const char delimiter = fileName[splitIndex];
    outDeviceName[splitIndex] = '\0';
    if (delimiter == '\0') {
      std::strcpy(outFilePath, outDeviceName);
      outDeviceName[0] = '\0';
      return;
    }

    std::int32_t pathSourceIndex = splitIndex + 1;
    if (pathSourceIndex == 2) {
      pathSourceIndex = 0;
      outDeviceName[0] = '\0';
    }

    std::int32_t pathWriteIndex = 0;
    while (pathSourceIndex < 297) {
      const char symbol = fileName[pathSourceIndex];
      if (symbol == '\0') {
        break;
      }
      outFilePath[pathWriteIndex] = symbol;
      ++pathWriteIndex;
      ++pathSourceIndex;
    }
    outFilePath[pathWriteIndex] = '\0';
    (void)toUpperStr(outDeviceName);
  }

  /**
   * Address: 0x00B12400 (FUN_00B12400, _getDefDev)
   *
   * What it does:
   * Copies the current default CVFS device name into caller storage.
   */
  char getDefDev(char* const outDeviceName)
  {
    const char firstChar = gCvFsDefaultDeviceName[0];
    if (firstChar != '\0') {
      const std::size_t byteCount = std::strlen(gCvFsDefaultDeviceName.data()) + 1u;
      std::memcpy(outDeviceName, gCvFsDefaultDeviceName.data(), byteCount);
      return firstChar;
    }

    outDeviceName[0] = '\0';
    return firstChar;
  }

  /**
   * Address: 0x00B133B0 (FUN_00B133B0, _isNeedDevName)
   *
   * What it does:
   * Returns whether a CVFS device requires `DEV:` name prefixes.
   */
  std::int32_t isNeedDevName(char* const deviceName)
  {
    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface != nullptr && deviceInterface->option != nullptr) {
      return deviceInterface->option(nullptr, 100, 0, 0);
    }
    return 0;
  }

  /**
   * Address: 0x00B133E0 (FUN_00B133E0, _addDevName)
   *
   * What it does:
   * Prefixes one file path with `DEV:` when the resolved device requires it.
   */
  std::int32_t addDevName(char* const deviceName, char* const filePath)
  {
    char* resolvedDeviceName = deviceName;
    if (resolvedDeviceName == nullptr) {
      resolvedDeviceName = gCvFsDefaultDeviceName.data();
    }

    const std::int32_t needsPrefix = isNeedDevName(resolvedDeviceName);
    if (needsPrefix == 1) {
      std::strcpy(gCvFsAddDevicePathScratch.data(), filePath);
      return std::sprintf(filePath, "%s:%s", resolvedDeviceName, gCvFsAddDevicePathScratch.data());
    }
    return needsPrefix;
  }

  /**
   * Address: 0x00B12290 (FUN_00B12290, _variousProc)
   *
   * What it does:
   * Resolves effective open-device and rewritten file path for CVFS operations.
   */
  CvFsDeviceInterfaceView* variousProc(char* const deviceName, char* const filePath, const char* const originalPath)
  {
    if (deviceName[0] == '\0') {
      (void)getDefDev(deviceName);
      if (deviceName[0] == '\0') {
        return nullptr;
      }
    }

    (void)addDevName(deviceName, filePath);
    CvFsDeviceInterfaceView* deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)getDefDev(deviceName);
      deviceInterface = getDevice(deviceName);
      if (deviceInterface != nullptr) {
        std::strcpy(filePath, originalPath);
      }
    }
    return deviceInterface;
  }

  /**
   * Address: 0x00B12160 (FUN_00B12160, _cvFsOpen)
   *
   * What it does:
   * Opens one CVFS handle through the resolved device interface.
   */
  extern "C" CvFsHandleView* cvFsOpen(char* const fileName, const std::int32_t openMode, const std::int32_t openFlags)
  {
    if (fileName == nullptr) {
      (void)cvFsError_(kCvFsErrOpenIllegalFileName);
      return nullptr;
    }

    char pathBuffer[kCvFsPathScratchBytes]{};
    char deviceBuffer[kCvFsPathScratchBytes]{};
    getDevName(deviceBuffer, pathBuffer, fileName);
    if (pathBuffer[0] == '\0') {
      (void)cvFsError_(kCvFsErrOpenIllegalFileName);
      return nullptr;
    }

    CvFsHandleView* const handle = allocCvFsHn();
    if (handle == nullptr) {
      (void)cvFsError_(kCvFsErrOpenHandleAllocFailed);
      return nullptr;
    }

    CvFsDeviceInterfaceView* const deviceInterface = variousProc(deviceBuffer, pathBuffer, fileName);
    handle->interfaceView = deviceInterface;
    if (deviceInterface == nullptr) {
      (void)releaseCvFsHn(handle);
      (void)cvFsError_(kCvFsErrOpenDeviceNotFound);
      return nullptr;
    }

    if (deviceInterface->openFile == nullptr) {
      (void)releaseCvFsHn(handle);
      (void)cvFsError_(kCvFsErrOpenVtableError);
      return nullptr;
    }

    const std::int32_t openedHandle = deviceInterface->openFile(pathBuffer, openMode, openFlags);
    handle->handleAddress = openedHandle;
    if (openedHandle == 0) {
      (void)releaseCvFsHn(handle);
      (void)cvFsError_(kCvFsErrOpenFailed);
      return nullptr;
    }

    return handle;
  }

  /**
   * Address: 0x00B13320 (FUN_00B13320, _cvFsSetDefVol)
   *
   * What it does:
   * Pushes one default-volume option packet to the selected CVFS device.
   */
  void cvFsSetDefVol(char* const deviceName, const std::int32_t volumeName)
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrSetDefVolInvalidDeviceName);
      return;
    }
    if (volumeName == 0) {
      (void)cvFsError_(kCvFsErrSetDefVolInvalidVolumeName);
      return;
    }

    CvFsDeviceInterfaceView* const deviceInterface = getDevice(deviceName);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrSetDefVolDeviceNotFound);
      return;
    }

    std::int32_t optionValues[5]{};
    optionValues[1] = volumeName;
    if (deviceInterface->option != nullptr) {
      (void)deviceInterface->option(optionValues, 6, 0, 0);
    }
  }

  /**
   * Address: 0x00B11ED0 (FUN_00B11ED0, _cvFsAddDev)
   *
   * What it does:
   * Validates and registers one CVFS device interface, then installs the
   * shared user-error bridge callback when the device supports it.
   */
  void cvFsAddDev(const char* const deviceName, void* (__cdecl* const deviceFactory)())
  {
    if (deviceName == nullptr) {
      (void)cvFsError_(kCvFsErrAddDevInvalidDeviceName);
      return;
    }
    if (deviceFactory == nullptr) {
      (void)cvFsError_(kCvFsErrAddDevInvalidInterfaceFn);
      return;
    }

    auto* const deviceInterface = addDevice(deviceName, deviceFactory);
    if (deviceInterface == nullptr) {
      (void)cvFsError_(kCvFsErrAddDevFailed);
      return;
    }

    if (deviceInterface->registerUserErrorBridge != nullptr) {
      deviceInterface->registerUserErrorBridge(&cvFsCallUsrErrFn, 0);
    }
  }

  /**
   * Address: 0x00B07B90 (FUN_00B07B90, _ADXPC_SetupFileSystem)
   *
   * What it does:
   * Initializes ADXPC file-device lanes and applies optional root-directory
   * override from `rootDirArgv[0]`.
   */
  int ADXPC_SetupFileSystem(const char** const rootDirArgv)
  {
    (void)ADXPC_GetVersion();
    (void)cvFsEntryErrFunc(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&ADXPC_ReportDvdError)), 0);

    cvFsAddDev(kCvFsDeviceMf, &mfCiGetInterface);
    xeCiInit();
    cvFsAddDev(kCvFsDeviceWx, &xeCiGetInterface);
    (void)cvFsSetDefDev(kCvFsDeviceWx);

    const char* const rootDir = (rootDirArgv != nullptr) ? *rootDirArgv : nullptr;
    return xeDirSetRootDir(rootDir);
  }

  /**
   * Address: 0x00B07C10 (FUN_00B07C10, _ADXPC_ShutdownFileSystem)
   *
   * What it does:
   * Shuts down ADXPC file-system lanes, finalizing ADXFIC first when ADXT is initialized.
   */
  char* ADXPC_ShutdownFileSystem()
  {
    if (ADXT_IsInitialized() > 0) {
      ADXFIC_Finish();
    }
    cvFsFinish();
    return xeCiFinish();
  }

  /**
   * Address: 0x00B07C30 (FUN_00B07C30, j__ADXPC_ShutdownFileSystem)
   *
   * What it does:
   * Thunk alias that jumps to `ADXPC_ShutdownFileSystem`.
   */
  char* ADXPC_ShutdownFileSystemThunk()
  {
    return ADXPC_ShutdownFileSystem();
  }

  /**
   * Address: 0x00B07C50 (FUN_00B07C50, nullsub_31)
   *
   * What it does:
   * No-op ADXPC callback lane.
   */
  void ADXPC_NoOpShutdownCallback()
  {
  }

  /**
   * Address: 0x00B07C60 (FUN_00B07C60, sub_B07C60)
   *
   * What it does:
   * Enables ADXPC DVD-error reporting mode lane.
   */
  std::int32_t ADXPC_EnableDvdErrorReporting()
  {
    return ADXPC_SetDvdErrorReportingEnabled(1);
  }

  /**
   * Address: 0x00B07C70 (FUN_00B07C70, sub_B07C70)
   *
   * What it does:
   * Disables ADXPC DVD-error reporting mode lane.
   */
  std::int32_t ADXPC_DisableDvdErrorReporting()
  {
    return ADXPC_SetDvdErrorReportingEnabled(0);
  }
