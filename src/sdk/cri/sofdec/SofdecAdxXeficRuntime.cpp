
  /**
   * Address: 0x00B2C5A0 (_ADX_SetDecodeSteAsMonoSw)
   *
   * What it does:
   * Sets stereo-float decode output mode lane (`mono` or `stereo`).
   */
  std::int32_t ADX_SetDecodeSteAsMonoSw(const std::int32_t outputAsMono)
  {
    adx_decode_output_mono_flag = outputAsMono;
    return outputAsMono;
  }

  /**
   * Address: 0x00B2CC90 (_ADX_DecodeSteFloat)
   *
   * What it does:
   * Dispatches stereo-float ADX decode to mono or stereo path based on runtime
   * switch lane.
   */
  std::int32_t ADX_DecodeSteFloat(
    char* sourceBytes,
    const std::int32_t blockCount,
    std::uint16_t* outLeftSamples,
    std::int16_t* leftHistory,
    std::uint16_t* outRightSamples,
    std::int16_t* rightHistory,
    const std::int16_t decodeScale,
    const float scaleFactor
  )
  {
    if (adx_decode_output_mono_flag != 0) {
      return ADX_DecodeSteFloatAsMono(
        sourceBytes,
        blockCount,
        outLeftSamples,
        leftHistory,
        outRightSamples,
        rightHistory,
        decodeScale,
        scaleFactor
      );
    }

    return ADX_DecodeSteFloatAsSte(
      sourceBytes,
      blockCount,
      outLeftSamples,
      leftHistory,
      outRightSamples,
      rightHistory,
      decodeScale,
      scaleFactor
    );
  }

  /**
   * Address: 0x00B1F300 (FUN_00B1F300)
   *
   * What it does:
   * Returns the global XEFIC initialization count lane.
   */
  LONG __cdecl xefic_GetInitializeCount()
  {
    return xefic_initialize_count;
  }

  /**
   * Address: 0x00B14510 (FUN_00B14510, _ADXT_IsInitialized)
   *
   * What it does:
   * ADXT wrapper that returns current XEFIC initialization count.
   */
  std::int32_t ADXT_IsInitialized()
  {
    return static_cast<std::int32_t>(xefic_GetInitializeCount());
  }

  /**
   * Address: 0x00B1F320 (FUN_00B1F320, _xefic_Initialize)
   *
   * What it does:
   * Performs first-time XEFIC global initialization: lock/thread startup,
   * object-pool reset, probe callback lane wiring, and read-mode setup.
   */
  void __cdecl xefic_Initialize()
  {
    if (InterlockedIncrement(&xefic_initialize_count) != 1) {
      return;
    }

    xefic_init_lock();
    xeci_create_thread();
    std::memset(xefic_crs, 0, sizeof(xefic_crs));
    xeci_file_size_probe_callback = &wxFicGetCachedFileSizeBytes;
    xeci_open_probe_callback = &wxFicGetCachedHandleAndInfo;
    xeci_set_read_mode(0, 0, 0, 1);
  }

  /**
   * Address: 0x00B1F310 (FUN_00B1F310, _XEFIC_Initialize)
   *
   * What it does:
   * Public thunk wrapper for XEFIC initialization lane.
   */
  void XEFIC_Initialize()
  {
    xefic_Initialize();
  }

  /**
   * Address: 0x00B1F390 (FUN_00B1F390, _xefic_Finalize)
   *
   * What it does:
   * Decrements XEFIC initialization count and, on final release, cleans every
   * active object, clears probe callback lanes, stops worker thread, and drops lock.
   */
  LONG __cdecl xefic_Finalize()
  {
    const LONG remainingInitCount = InterlockedDecrement(&xefic_initialize_count);
    if (remainingInitCount != 0) {
      return remainingInitCount;
    }

    for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
      if (object->used != 0) {
        xefic_cleanup_obj(object);
      }
    }

    xeci_file_size_probe_callback = nullptr;
    std::memset(xefic_crs, 0, sizeof(xefic_crs));
    xeci_open_probe_callback = nullptr;
    xeci_destroy_thread();
    xefic_delete_lock();
    return remainingInitCount;
  }

  /**
   * Address: 0x00B1F380 (FUN_00B1F380, _XEFIC_Finalize)
   *
   * What it does:
   * Public thunk wrapper for XEFIC finalize lane.
   */
  LONG XEFIC_Finalize()
  {
    return xefic_Finalize();
  }

  /**
   * Address: 0x00B14520 (FUN_00B14520, _ADXFIC_Init)
   *
   * What it does:
   * ADXFIC reference-counted init wrapper; initializes XEFIC on first acquire.
   */
  void ADXFIC_Init()
  {
    if (InterlockedIncrement(&adxfic_init_count) == 1) {
      XEFIC_Initialize();
    }
  }

  /**
   * Address: 0x00B14540 (FUN_00B14540, _ADXFIC_Finish)
   *
   * What it does:
   * ADXFIC reference-counted finalize wrapper; finalizes XEFIC when last
   * ADXFIC owner releases.
   */
  LONG ADXFIC_Finish()
  {
    const LONG remainingRefCount = InterlockedDecrement(&adxfic_init_count);
    if (remainingRefCount != 0) {
      return remainingRefCount;
    }
    return XEFIC_Finalize();
  }

  /**
   * Address: 0x00B14560 (FUN_00B14560)
   *
   * What it does:
   * Returns required XEFIC queue work bytes for one path/depth lane, or `-1`
   * when path input is null.
   */
  std::int32_t __cdecl ADXFIC_GetRequiredWorkBytes(const char* const rootPath, const std::int32_t pathEnumerationMode)
  {
    if (rootPath == nullptr) {
      return -1;
    }
    return xefic_CalculateRequiredQueueWorkBytes(rootPath, pathEnumerationMode);
  }

  /**
   * Address: 0x00B1F4F0 (FUN_00B1F4F0)
   *
   * What it does:
   * Creates one XEFIC object and immediately rebuilds its queue synchronously,
   * then transitions state lanes to active/error-complete form.
   */
  XeficObject* __cdecl xefic_CreateObjectAndBuildQueueSync(
    const char* const rootPath,
    const std::int32_t pathEnumerationMode,
    void* const externalWorkBuffer,
    const std::int32_t externalWorkBufferBytes
  )
  {
    if (xefic_initialize_count == 0) {
      XEFIC_Initialize();
    }

    XeficObject* const object = xefic_CreateObjectLocked(
      rootPath,
      pathEnumerationMode,
      externalWorkBuffer,
      externalWorkBufferBytes
    );
    if (object == nullptr) {
      return nullptr;
    }

    object->state = 1;
    xefic_RebuildObjectQueue(object);
    object->queueCursor = object->queueHead;
    if (xefic_work_complete_callback != nullptr) {
      xefic_work_complete_callback(object);
    }
    if (object->state != 6) {
      object->state = 2;
    }
    return object;
  }

  /**
   * Address: 0x00B14580 (FUN_00B14580)
   *
   * What it does:
   * Creates one XEFIC object and performs synchronous queue build when path is
   * non-null; otherwise returns null.
   */
  XeficObject* __cdecl ADXFIC_CreateObjectAndBuildQueueSync(
    const char* const rootPath,
    const std::int32_t pathEnumerationMode,
    void* const externalWorkBuffer,
    const std::int32_t externalWorkBufferBytes
  )
  {
    if (rootPath == nullptr) {
      return nullptr;
    }
    return xefic_CreateObjectAndBuildQueueSync(
      rootPath,
      pathEnumerationMode,
      externalWorkBuffer,
      externalWorkBufferBytes
    );
  }

  /**
   * Address: 0x00B145A0 (FUN_00B145A0)
   *
   * What it does:
   * Creates one XEFIC object for async queue build when path is non-null;
   * otherwise returns null.
   */
  XeficObject* __cdecl ADXFIC_CreateObjectForAsyncQueueBuild(
    const char* const rootPath,
    const std::int32_t pathEnumerationMode,
    void* const externalWorkBuffer,
    const std::int32_t externalWorkBufferBytes
  )
  {
    if (rootPath == nullptr) {
      return nullptr;
    }
    return xefic_CreateObjectForAsyncQueueBuild(
      rootPath,
      pathEnumerationMode,
      externalWorkBuffer,
      externalWorkBufferBytes
    );
  }

  /**
   * Address: 0x00B145E0 (FUN_00B145E0)
   *
   * What it does:
   * Cleans up one XEFIC object when object pointer is non-null.
   */
  void __cdecl ADXFIC_CleanupObject(XeficObject* const object)
  {
    if (object != nullptr) {
      xefic_cleanup_obj(object);
    }
  }

  /**
   * Address: 0x00B14600 (FUN_00B14600)
   *
   * What it does:
   * Forwards ADXFIC open-result probe callback install to XEFIC callback lane.
   */
  XeficOpenResultProbeCallback __cdecl
  ADXFIC_SetOpenResultProbeCallback(const XeficOpenResultProbeCallback callback, const std::int32_t callbackContext)
  {
    return xefic_SetOpenResultProbeCallback(callback, callbackContext);
  }

  /**
   * Address: 0x00B1F3F0 (FUN_00B1F3F0)
   *
   * What it does:
   * Builds rooted path context and runs one XEFIND pass that accumulates queue
   * payload bytes needed for all relative entries under that path.
   */
  std::int32_t __cdecl
  xefic_CalculateRequiredQueueWorkBytes(const char* const rootPath, const std::int32_t pathEnumerationMode)
  {
    XeficCacheBuildSizeContext workSizeContext{};
    char rootedPath[MAX_PATH]{};
    if (rootPath != nullptr) {
      std::strcpy(rootedPath, rootPath);
    } else {
      std::memset(rootedPath, 0, sizeof(rootedPath));
    }
    xeDirAppendRootDir(rootedPath, rootPath);

    const auto rootedPathLengthWithNull = std::strlen(rootedPath) + 1u;
    auto pathPrefixLength = static_cast<std::int32_t>(rootedPathLengthWithNull - 1u);
    if (rootedPath[pathPrefixLength] == '\\') {
      --pathPrefixLength;
      rootedPath[pathPrefixLength] = '\0';
    }

    workSizeContext.pathPrefixLength = pathPrefixLength;
    workSizeContext.accumulatedWorkBytes = xeci_aligned_str_size(rootedPath);

    while (InterlockedIncrement(&xefic_search_guard) != 1) {
      InterlockedDecrement(&xefic_search_guard);
      Sleep(kXeficWorkerSleepMilliseconds);
    }

    (void)xefind_SetVisitCallback(&xefic_AccumulateEntryWorkSize, &workSizeContext);
    const std::int32_t searchResult = xefind_Search(rootedPath, pathEnumerationMode, nullptr);
    if (searchResult >= 0) {
      InterlockedDecrement(&xefic_search_guard);
      return workSizeContext.accumulatedWorkBytes;
    }
    return searchResult;
  }

  /**
   * Address: 0x00B1F590 (FUN_00B1F590)
   *
   * What it does:
   * Reserves one free XEFIC object slot, initializes work lanes/path prefix
   * storage, and prepares queue head/cursor lanes for cache-entry append.
   */
  XeficObject* __cdecl xefic_CreateObjectUnlocked(
    const char* const rootPath,
    const std::int32_t pathEnumerationMode,
    void* const externalWorkBuffer,
    const std::int32_t externalWorkBufferBytes
  )
  {
    XeficObject* freeObject = nullptr;
    for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
      if (object->used == 0) {
        freeObject = object;
        break;
      }
    }

    if (freeObject == nullptr) {
      return nullptr;
    }

    freeObject->pathEnumerationMode = pathEnumerationMode;
    freeObject->queuedEntryCount = 0;
    if (externalWorkBuffer != nullptr) {
      freeObject->workBuffer = externalWorkBuffer;
      freeObject->workBufferBytes = externalWorkBufferBytes;
    } else {
      freeObject->hasHeapAllocation = 1;
      freeObject->workBufferBytes = xefic_CalculateRequiredQueueWorkBytes(rootPath, pathEnumerationMode);
    }

    xefic_InitializeObjectWorkBuffer(freeObject);

    char rootedPath[MAX_PATH]{};
    if (rootPath != nullptr) {
      std::strcpy(rootedPath, rootPath);
    } else {
      std::memset(rootedPath, 0, sizeof(rootedPath));
    }
    xeDirAppendRootDir(rootedPath, rootPath);

    const auto rootedPathLengthWithNull = std::strlen(rootedPath) + 1u;
    auto pathPrefixLength = static_cast<std::int32_t>(rootedPathLengthWithNull - 1u);
    if (rootedPath[pathPrefixLength] == '\\') {
      --pathPrefixLength;
      rootedPath[pathPrefixLength] = '\0';
    }

    freeObject->pathPrefixLength = pathPrefixLength;
    freeObject->pathPrefix = static_cast<char*>(freeObject->workBuffer);
    std::strcpy(static_cast<char*>(freeObject->workBuffer), rootedPath);

    const std::int32_t alignedPrefixBytes = xeci_aligned_str_size(freeObject->pathPrefix);
    if ((alignedPrefixBytes + freeObject->usedWorkBytes) <= freeObject->workBufferBytes) {
      freeObject->usedWorkBytes = alignedPrefixBytes;
      auto* const queueStorageStart = reinterpret_cast<XeficQueuedFileEntry*>(
        static_cast<char*>(freeObject->workBuffer) + alignedPrefixBytes
      );
      freeObject->used = 1;
      freeObject->queueHead = queueStorageStart;
      freeObject->queueCursor = queueStorageStart;
      return freeObject;
    }

    xeci_error(0, kXeficInitialWorkBufferShortMessage);
    return nullptr;
  }

  /**
   * Address: 0x00B1F560 (FUN_00B1F560)
   *
   * What it does:
   * Acquires XEFIC lock and creates one object slot with initialized queue
   * work lanes, then releases the lock and returns the created object.
   */
  XeficObject* __cdecl xefic_CreateObjectLocked(
    const char* const rootPath,
    const std::int32_t pathEnumerationMode,
    void* const externalWorkBuffer,
    const std::int32_t externalWorkBufferBytes
  )
  {
    xefic_lock();
    XeficObject* const object = xefic_CreateObjectUnlocked(
      rootPath,
      pathEnumerationMode,
      externalWorkBuffer,
      externalWorkBufferBytes
    );
    xefic_unlock();
    return object;
  }

  /**
   * Address: 0x00B1F6D0 (FUN_00B1F6D0)
   *
   * What it does:
   * Ensures XEFIC subsystem init, creates one object, and marks its state/work
   * lanes so the server pass can rebuild queued cache entries asynchronously.
   */
  XeficObject* __cdecl xefic_CreateObjectForAsyncQueueBuild(
    const char* const rootPath,
    const std::int32_t pathEnumerationMode,
    void* const externalWorkBuffer,
    const std::int32_t externalWorkBufferBytes
  )
  {
    if (xefic_initialize_count == 0) {
      XEFIC_Initialize();
    }

    XeficObject* const object = xefic_CreateObjectLocked(
      rootPath,
      pathEnumerationMode,
      externalWorkBuffer,
      externalWorkBufferBytes
    );
    if (object == nullptr) {
      return nullptr;
    }

    xefic_lock();
    object->state = 1;
    object->hasWork = 1;
    xefic_unlock();
    return object;
  }

  /**
   * Address: 0x00B1F7D0 (FUN_00B1F7D0)
   *
   * What it does:
   * Revalidation callback: resolves matching cached queue entry and marks cache
   * state lane `2` when current file size exceeds cached size by at least 0x800.
   */
  std::int32_t __cdecl xefic_RevalidateQueuedEntryStateCallback(
    const XefindFoundFileInfo* const foundFile,
    void* const callbackContext
  )
  {
    auto* const object = static_cast<XeficObject*>(callbackContext);
    char* const foundPath = const_cast<char*>(foundFile->path);
    foundPath[0] = object->pathPrefix[0];

    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(foundPath);
    if (queueEntry != nullptr &&
        static_cast<std::int32_t>(foundFile->fileSizeLow) >= (queueEntry->fileSizeBytes + 0x800)) {
      queueEntry->cacheState = 2;
    }
    return 0;
  }

  /**
   * Address: 0x00B1F720 (FUN_00B1F720)
   *
   * What it does:
   * Runs one guarded XEFIND pass for a rooted path and uses revalidation
   * callback lanes to refresh queued entry cache-state markers.
   */
  LONG __cdecl xefic_RevalidateQueuedEntryStates(XeficObject* const object, const char* const rootPath)
  {
    char rootedPath[MAX_PATH]{};
    if (rootPath != nullptr) {
      std::strcpy(rootedPath, rootPath);
    } else {
      std::memset(rootedPath, 0, sizeof(rootedPath));
    }
    xeDirAppendRootDir(rootedPath, rootPath);

    while (InterlockedIncrement(&xefic_search_guard) != 1) {
      InterlockedDecrement(&xefic_search_guard);
      Sleep(kXeficWorkerSleepMilliseconds);
    }

    (void)xefind_SetVisitCallback(&xefic_RevalidateQueuedEntryStateCallback, object);
    xefind_Search(rootedPath, object->pathEnumerationMode, nullptr);
    return InterlockedDecrement(&xefic_search_guard);
  }

  /**
   * Address: 0x00B1F810 (FUN_00B1F810)
   *
   * What it does:
   * Ensures one XEFIC object has an initialized work buffer (optional heap
   * allocation path), then clears that work buffer range to zero.
   */
  std::int32_t __cdecl xefic_InitializeObjectWorkBuffer(XeficObject* const object)
  {
    if (object->hasHeapAllocation != 0) {
      const HANDLE processHeap = GetProcessHeap();
      if (processHeap == nullptr) {
        xeci_error(0, kXeficGetHeapHandleFailedMessage);
        return -1;
      }

      void* const allocatedBuffer = HeapAlloc(processHeap, 0, static_cast<SIZE_T>(object->workBufferBytes));
      if (allocatedBuffer == nullptr) {
        xeci_error(0, kXeficAllocateWorkBufferFailedMessage);
        return -1;
      }

      object->heapHandle = processHeap;
      object->workBuffer = allocatedBuffer;
    }

    std::memset(object->workBuffer, 0, static_cast<std::size_t>(static_cast<std::uint32_t>(object->workBufferBytes)));
    return 0;
  }

  /**
   * Address: 0x00B1F890 (FUN_00B1F890, xefic_cleanup_obj)
   *
   * What it does:
   * Runs optional object cleanup callback, waits for pending work completion,
   * releases queued handles/work buffer lanes, then zeroes object state under
   * XEFIC lock.
   */
  void __cdecl xefic_cleanup_obj(XeficObject* const object)
  {
    if (xefic_object_cleanup_callback != nullptr) {
      xefic_object_cleanup_callback(object);
    }

    xefic_wait_on_obj(object);
    xefic_CloseObjectQueuedHandles(object);
    xefic_ReleaseObjectWorkBuffer(object);

    xefic_lock();
    std::memset(object, 0, sizeof(XeficObject));
    xefic_unlock();
  }

  /**
   * Address: 0x00B1F8D0 (FUN_00B1F8D0)
   *
   * What it does:
   * Installs/updates optional XEFIC open-result probe callback and callback
   * context lanes used during queue build.
   */
  XeficOpenResultProbeCallback __cdecl
  xefic_SetOpenResultProbeCallback(const XeficOpenResultProbeCallback callback, const std::int32_t callbackContext)
  {
    xefic_open_result_probe_callback = callback;
    xefic_open_result_probe_context = callbackContext;
    return callback;
  }

  /**
   * Address: 0x00B1F8F0 (FUN_00B1F8F0)
   *
   * What it does:
   * Closes and clears all queued file-entry handles for one XEFIC object.
   */
  void __cdecl xefic_CloseObjectQueuedHandles(XeficObject* const object)
  {
    xefic_ForEachQueuedEntryOnObjectLocked(object, &xefic_CloseQueuedEntryHandleAndReset, 0);
  }

  /**
   * Address: 0x00B1F910 (FUN_00B1F910)
   *
   * What it does:
   * Closes one queued XEFIC file handle lane under temporary thread-priority
   * elevation, then clears handle/size/state lanes in the queue entry.
   */
  std::int32_t __cdecl xefic_CloseQueuedEntryHandleAndReset(
    XeficQueuedFileEntry* const queueEntry,
    [[maybe_unused]] const std::int32_t contextValue
  )
  {
    const HANDLE queuedHandle = queueEntry->fileHandle;
    if (queuedHandle != nullptr) {
      xeci_save_thread_prio();
      CloseHandle(queuedHandle);
      xeci_set_thread_prio();
    }

    queueEntry->fileHandle = nullptr;
    queueEntry->fileSizeBytes = 0;
    queueEntry->cacheState = 0;
    return 0;
  }

  /**
   * Address: 0x00B1F950 (FUN_00B1F950)
   *
   * What it does:
   * Clears one XEFIC object work buffer lane and, when heap-backed, frees the
   * work allocation and resets heap/work pointers.
   */
  std::int32_t __cdecl xefic_ReleaseObjectWorkBuffer(XeficObject* const object)
  {
    void* const workBuffer = object->workBuffer;
    const auto workBufferBytes = static_cast<std::size_t>(static_cast<std::uint32_t>(object->workBufferBytes));
    std::memset(workBuffer, 0, workBufferBytes);

    std::int32_t result = object->hasHeapAllocation;
    if (result != 0) {
      result = HeapFree(object->heapHandle, 0, workBuffer);
      object->heapHandle = nullptr;
      object->workBuffer = nullptr;
      object->workBufferBytes = 0;
    }

    return result;
  }

  /**
   * Address: 0x00B1F9A0 (FUN_00B1F9A0, xefic_wait_on_obj)
   *
   * What it does:
   * Polls one XEFIC object work-state lane until worker processing completes.
   */
  std::int32_t __cdecl xefic_wait_on_obj(XeficObject* const object)
  {
    std::int32_t result = object->hasWork;
    while (result != 0) {
      Sleep(kXeficWorkerSleepMilliseconds);
      result = object->hasWork;
    }
    return result;
  }

  /**
   * Address: 0x00B1FAA0 (FUN_00B1FAA0)
   *
   * What it does:
   * XEFIND callback that opens one discovered file, appends a queue entry into
   * the object's work buffer, and advances queue-builder lanes.
   */
  std::int32_t __cdecl xefic_QueueFoundFileForObject(
    const XefindFoundFileInfo* const foundFile,
    void* const callbackContext
  )
  {
    const char* const filePath = foundFile->path;
    const std::int32_t fileSizeBytes = static_cast<std::int32_t>(foundFile->fileSizeLow);
    auto* const object = static_cast<XeficObject*>(callbackContext);
    auto* const queueEntryWriteCursor = object->queueCursor;

    xeci_save_thread_prio();
    const DWORD openFlags = (xeci_read_file_mode != 0) ? 0x10000000u : 0x60000000u;
    const HANDLE openedHandle = CreateFileA(
      filePath,
      GENERIC_READ,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_EXISTING,
      openFlags,
      nullptr
    );
    xeci_set_thread_prio();

    if (xefic_open_result_probe_callback != nullptr) {
      xefic_open_result_probe_callback(filePath, fileSizeBytes, openedHandle, xefic_open_result_probe_context);
    }

    if (openedHandle == INVALID_HANDLE_VALUE || fileSizeBytes < 0) {
      std::sprintf(wxfic_cache_file, kXeficBuildQueueOpenErrorFormat, filePath);
      xeci_error(0, wxfic_cache_file);
      object->stateSignal = 1;
      object->state = 6;
      return 0;
    }

    const char* const relativePath = filePath + object->pathPrefixLength;
    const std::int32_t queueEntrySpan = xeci_aligned_str_size(relativePath) + 0x14;
    const std::int32_t nextUsedWorkBytes = queueEntrySpan + object->usedWorkBytes;
    object->usedWorkBytes = nextUsedWorkBytes;
    if (nextUsedWorkBytes <= object->workBufferBytes) {
      queueEntryWriteCursor->fileSizeBytes = fileSizeBytes;
      queueEntryWriteCursor->fileHandle = openedHandle;
      queueEntryWriteCursor->next = reinterpret_cast<XeficQueuedFileEntry*>(
        reinterpret_cast<char*>(queueEntryWriteCursor) + queueEntrySpan
      );
      auto* const relativePathStorage = reinterpret_cast<char*>(queueEntryWriteCursor) + 0x14;
      queueEntryWriteCursor->relativePath = relativePathStorage;
      std::strcpy(relativePathStorage, relativePath);
      ++object->queuedEntryCount;
      object->queueCursor = queueEntryWriteCursor->next;
      return 0;
    }

    xeci_error(0, kXeficWorkBufferShortMessage);
    object->stateSignal = 1;
    object->state = 6;
    return -1;
  }

  /**
   * Address: 0x00B1F9D0 (FUN_00B1F9D0)
   *
   * What it does:
   * Acquires XEFIC search guard lane, installs queue-build callback, executes
   * one file enumeration pass for the object path, then releases guard on
   * successful completion.
   */
  std::int32_t __cdecl xefic_RebuildObjectQueue(XeficObject* const object)
  {
    while (InterlockedIncrement(&xefic_search_guard) != 1) {
      InterlockedDecrement(&xefic_search_guard);
      Sleep(kXeficWorkerSleepMilliseconds);
    }

    (void)xefind_SetVisitCallback(&xefic_QueueFoundFileForObject, object);
    const std::int32_t searchResult =
      xefind_Search(const_cast<char*>(object->pathPrefix), object->pathEnumerationMode, nullptr);
    if (searchResult >= 0) {
      InterlockedDecrement(&xefic_search_guard);
      return 0;
    }
    return searchResult;
  }

  /**
   * Address: 0x00B1FA40 (FUN_00B1FA40, xeci_aligned_str_size)
   *
   * char const *
   *
   * IDA signature:
   * signed int __cdecl xeci_aligned_str_size(const char *a1);
   *
   * What it does:
   * Returns source string byte count including null terminator, aligned to the
   * next 4-byte boundary.
   */
  std::int32_t __cdecl xeci_aligned_str_size(const char* const text)
  {
    std::int32_t alignedSize = static_cast<std::int32_t>(std::strlen(text)) + 1;
    const std::int32_t remainder = alignedSize & 3;
    if (remainder != 0) {
      alignedSize += 4 - remainder;
    }
    return alignedSize;
  }

  /**
   * Address: 0x00B1FA70 (FUN_00B1FA70)
   *
   * _DWORD *, int
   *
   * IDA signature:
   * int __cdecl sub_B1FA70(_DWORD *a1, int a2);
   *
   * What it does:
   * Accumulates per-entry XEFIC cache work size using aligned relative-path
   * length plus one fixed 0x14-byte entry header lane.
   */
  std::int32_t __cdecl xefic_AccumulateEntryWorkSize(
    const XefindFoundFileInfo* const foundFile,
    void* const callbackContext
  )
  {
    auto* const context = static_cast<XeficCacheBuildSizeContext*>(callbackContext);
    const char* const entryPath = foundFile->path;
    const char* const relativePath = entryPath + context->pathPrefixLength;
    context->accumulatedWorkBytes += xeci_aligned_str_size(relativePath) + 0x14;
    return 0;
  }

  std::int32_t __cdecl xefic_GetObjectUsedWorkBytes(const XeficObject* object);
  const char* __cdecl xefic_GetObjectPathPrefix(const XeficObject* object);
  const char* __cdecl xefic_GetQueuedRelativePathByIndexLocked(XeficObject* object, std::int32_t entryIndex);
  BOOL __cdecl wxFicHasCachedHandle(const char* fileName);
  void __cdecl wxFicDisableFile(std::int32_t callbackContext, const char* fileName);
  void __cdecl wxFicEnableFile(std::int32_t callbackContext, LPCSTR fileName);
  void xefic_DebugDumpQueueForObjectLocked(XeficObject* object);

  /**
   * Address: 0x00B14610 (FUN_00B14610, sub_B14610)
   *
   * What it does:
   * Returns queued-entry count for one XEFIC object, or `-1` for null object.
   */
  [[maybe_unused]] std::int32_t xefic_GetQueuedEntryCountOrMinusOne(const XeficObject* const object)
  {
    if (object != nullptr) {
      return xefic_GetQueuedEntryCount(object);
    }
    return -1;
  }

  /**
   * Address: 0x00B14630 (FUN_00B14630, sub_B14630)
   *
   * What it does:
   * Returns used-work-byte count for one XEFIC object, or `-1` for null object.
   */
  [[maybe_unused]] std::int32_t xefic_GetUsedWorkBytesOrMinusOne(const XeficObject* const object)
  {
    if (object != nullptr) {
      return xefic_GetObjectUsedWorkBytes(object);
    }
    return -1;
  }

  /**
   * Address: 0x00B14650 (FUN_00B14650, sub_B14650)
   *
   * What it does:
   * Returns one XEFIC object path-prefix lane when object is valid.
   */
  [[maybe_unused]] const char* xefic_GetObjectPathPrefixOrNull(const XeficObject* const object)
  {
    if (object != nullptr) {
      return xefic_GetObjectPathPrefix(object);
    }
    return reinterpret_cast<const char*>(object);
  }

  /**
   * Address: 0x00B14670 (FUN_00B14670, sub_B14670)
   *
   * What it does:
   * Returns queued relative-path by index for one XEFIC object when valid.
   */
  [[maybe_unused]]
  const char* xefic_GetQueuedRelativePathByIndexOrNull(XeficObject* const object, const std::int32_t entryIndex)
  {
    if (object != nullptr) {
      return xefic_GetQueuedRelativePathByIndexLocked(object, entryIndex);
    }
    return reinterpret_cast<const char*>(object);
  }

  /**
   * Address: 0x00B14690 (FUN_00B14690, sub_B14690)
   *
   * What it does:
   * Returns cached-handle presence for one path when pointer is valid.
   */
  [[maybe_unused]] BOOL wxFicHasCachedHandleOrFalse(const char* const fileName)
  {
    if (fileName != nullptr) {
      return wxFicHasCachedHandle(fileName);
    }
    return FALSE;
  }

  /**
   * Address: 0x00B146B0 (FUN_00B146B0, sub_B146B0)
   *
   * What it does:
   * Calls cached-file disable helper when both callback context and path are
   * valid, returning the input file-name lane.
   */
  [[maybe_unused]]
  const char* wxFicDisableFileIfValid(const std::int32_t callbackContext, const char* const fileName)
  {
    if (callbackContext != 0 && fileName != nullptr) {
      wxFicDisableFile(callbackContext, fileName);
    }
    return fileName;
  }

  /**
   * Address: 0x00B146D0 (FUN_00B146D0, sub_B146D0)
   *
   * What it does:
   * Calls cached-file enable helper when both callback context and path are
   * valid, returning the input file-name lane.
   */
  [[maybe_unused]]
  const char* wxFicEnableFileIfValid(const std::int32_t callbackContext, const char* const fileName)
  {
    if (callbackContext != 0 && fileName != nullptr) {
      wxFicEnableFile(callbackContext, fileName);
    }
    return fileName;
  }

  /**
   * Address: 0x00B146F0 (FUN_00B146F0, sub_B146F0)
   *
   * What it does:
   * Dumps one XEFIC object queue under lock when object pointer is valid.
   */
  [[maybe_unused]] XeficObject* xefic_DebugDumpQueueForObjectLockedIfValid(XeficObject* const object)
  {
    if (object != nullptr) {
      xefic_DebugDumpQueueForObjectLocked(object);
    }
    return object;
  }

  /**
   * Address: 0x00B1FBD0 (FUN_00B1FBD0)
   *
   * struct_sofdec_xefic_obj *
   *
   * IDA signature:
   * int __cdecl sub_B1FBD0(struct_sofdec_xefic_obj *a1);
   *
   * What it does:
   * Returns queued-entry count lane for one XEFIC object (`+0x30`).
   */
  std::int32_t __cdecl xefic_GetQueuedEntryCount(const XeficObject* const object)
  {
    return object->queuedEntryCount;
  }

  /**
   * Address: 0x00B1FD90 (FUN_00B1FD90)
   *
   * char *
   *
   * IDA signature:
   * int __cdecl sub_B1FD90(char *a2);
   *
   * What it does:
   * Resolves one path and finds matching cached XEFIC queued entry in unlocked
   * queue lanes.
   */
  XeficQueuedFileEntry* __cdecl xefic_FindQueuedFileEntryByPathUnlocked(const char* const fileName)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    return XeficFindQueuedFileEntryUnlockedByRootedPath(rootedFileName);
  }

  /**
   * Address: 0x00B1FBE0 (FUN_00B1FBE0)
   *
   * int
   *
   * IDA signature:
   * int __cdecl sub_B1FBE0(int a1);
   *
   * What it does:
   * Returns one XEFIC object used-work-bytes lane (`+0x20`).
   */
  std::int32_t __cdecl xefic_GetObjectUsedWorkBytes(const XeficObject* const object)
  {
    return object->usedWorkBytes;
  }

  /**
   * Address: 0x00B1FBF0 (FUN_00B1FBF0)
   *
   * struct_sofdec_xefic_obj *
   *
   * IDA signature:
   * const char *__cdecl sub_B1FBF0(struct_sofdec_xefic_obj *a1);
   *
   * What it does:
   * Returns one XEFIC object path-prefix lane (`+0x24`).
   */
  const char* __cdecl xefic_GetObjectPathPrefix(const XeficObject* const object)
  {
    return object->pathPrefix;
  }

  /**
   * Address: 0x00B1FC30 (FUN_00B1FC30)
   *
   * struct_sofdec_xefic_obj *, int
   *
   * IDA signature:
   * int __cdecl sub_B1FC30(struct_sofdec_xefic_obj *a1, int a2);
   *
   * What it does:
   * Returns queued relative-path lane at one index from a single XEFIC object
   * traversal, or null when index is out of range.
   */
  const char* __cdecl xefic_GetQueuedRelativePathByIndexUnlocked(XeficObject* const object, const std::int32_t entryIndex)
  {
    const auto queuedEntryCount = xefic_GetQueuedEntryCount(object);
    object->queueCursor = object->queueHead;
    if (queuedEntryCount <= 0) {
      return nullptr;
    }

    for (std::int32_t currentIndex = 0; currentIndex < queuedEntryCount; ++currentIndex) {
      const char* const relativePath = xefic_obj_pop_relative_path(object);
      if (currentIndex == entryIndex) {
        return relativePath;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00B1FC00 (FUN_00B1FC00)
   *
   * int, int
   *
   * IDA signature:
   * int __cdecl sub_B1FC00(int a1, int a2);
   *
   * What it does:
   * Locks XEFIC queue lanes, returns one queued relative-path lane by index,
   * then unlocks.
   */
  const char* __cdecl xefic_GetQueuedRelativePathByIndexLocked(XeficObject* const object, const std::int32_t entryIndex)
  {
    xefic_lock();
    const char* const relativePath = xefic_GetQueuedRelativePathByIndexUnlocked(object, entryIndex);
    xefic_unlock();
    return relativePath;
  }

  /**
   * Address: 0x00B1FC70 (FUN_00B1FC70)
   *
   * int, char *
   *
   * IDA signature:
   * int __cdecl sub_B1FC70(int _108, char *a2);
   *
   * What it does:
   * Resolves one path, applies `z -> d` drive-lane alias on rooted path start,
   * then returns cached file length in 0x800-byte sectors with ceil semantics.
   */
  std::int32_t __cdecl wxFicGetCachedSectorCount(
    [[maybe_unused]] const std::int32_t callbackContext,
    const char* const fileName
  )
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    if (rootedFileName[0] == 'z') {
      rootedFileName[0] = 'd';
    }

    const std::int32_t fileSizeBytes = wxFicGetCachedFileSizeBytes(rootedFileName);
    if (fileSizeBytes < 0) {
      return -1;
    }

    std::int32_t sectorCount = fileSizeBytes / 0x800;
    if ((fileSizeBytes % 0x800) > 0) {
      ++sectorCount;
    }
    return sectorCount;
  }

  /**
   * Address: 0x00B1FCE0 (FUN_00B1FCE0)
   *
   * int
   *
   * IDA signature:
   * int __cdecl sub_B1FCE0(int a1);
   *
   * What it does:
   * Pops one XEFIC queue entry and returns its relative-path lane.
   */
  const char* __cdecl xefic_obj_pop_relative_path(XeficObject* const object)
  {
    XeficQueuedFileEntry* const queueEntry = object->queueCursor;
    object->queueCursor = queueEntry->next;
    if (object->queueCursor == nullptr) {
      object->queueCursor = object->queueHead;
    }
    return queueEntry->relativePath;
  }

  /**
   * Address: 0x00B1FD00 (FUN_00B1FD00)
   *
   * char *
   *
   * IDA signature:
   * BOOL __cdecl sub_B1FD00(char *a2);
   *
   * What it does:
   * Returns whether one rooted file path has a cached XEFIC file handle.
   */
  BOOL __cdecl wxFicHasCachedHandle(const char* const fileName)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    return wxFicGetCachedHandle(rootedFileName) != nullptr ? TRUE : FALSE;
  }

  /**
   * Address: 0x00B1FD30 (FUN_00B1FD30, xeci_cmp_str_offset)
   *
   * char const *, char const *, int
   *
   * IDA signature:
   * int __cdecl xeci_cmp_str_offset(const char *substr, const char *str, int len);
   *
   * What it does:
   * Compares two string lanes case-insensitively for `len` bytes using one
   * caller-provided base-offset relation.
   */
  int __cdecl xeci_cmp_str_offset(const char* const substr, const char* const str, const std::int32_t len)
  {
    std::int32_t result = 0;
    if (len <= 0) {
      return result;
    }

    for (std::int32_t index = 0; index < len; ++index) {
      const auto lhs = static_cast<std::int32_t>(static_cast<std::uint8_t>(substr[index]) & 0xDFu);
      const auto rhs = static_cast<std::int32_t>(static_cast<std::uint8_t>(str[index]) & 0xDFu);
      result = lhs - rhs;
      if (result != 0) {
        break;
      }
    }
    return result;
  }

  /**
   * Address: 0x00B1FD70 (FUN_00B1FD70)
   *
   * char *
   *
   * IDA signature:
   * int __cdecl sub_B1FD70(char *a1);
   *
   * What it does:
   * Locks XEFIC queue lanes, looks up one queued file entry by rooted path,
   * then unlocks and returns the located entry pointer.
   */
  XeficQueuedFileEntry* __cdecl xefic_FindQueuedFileEntryByPathLocked(const char* const rootedFileName)
  {
    xefic_lock();
    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathUnlocked(rootedFileName);
    xefic_unlock();
    return queueEntry;
  }

  /**
   * Address: 0x00B1FE70 (FUN_00B1FE70, xefic_obj_pop)
   *
   * struct_sofdec_xefic_obj *
   *
   * IDA signature:
   * int __cdecl sub_B1FE70(struct_sofdec_xefic_obj *a1);
   *
   * What it does:
   * Pops current queue cursor entry from one XEFIC object and advances cursor
   * to next entry, wrapping to queue head when next is null.
   */
  XeficQueuedFileEntry* __cdecl xefic_obj_pop(XeficObject* const object)
  {
    XeficQueuedFileEntry* const queueEntry = object->queueCursor;
    object->queueCursor = queueEntry->next;
    if (object->queueCursor == nullptr) {
      object->queueCursor = object->queueHead;
    }
    return queueEntry;
  }

  /**
   * Address: 0x00B1FE90 (FUN_00B1FE90)
   *
   * char *, int *, int *
   *
   * IDA signature:
   * _DWORD *__cdecl sub_B1FE90(char *a2, _DWORD *arg4, _DWORD *a3);
   *
   * What it does:
   * Returns cached file handle for one path and optionally writes cached
   * file-size/state lanes to caller output pointers.
   */
  HANDLE __cdecl wxFicGetCachedHandleAndInfo(
    const char* const fileName,
    std::int32_t* const outFileSizeBytes,
    std::int32_t* const outCacheState
  )
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(rootedFileName);
    if (queueEntry == nullptr) {
      return nullptr;
    }

    if (outFileSizeBytes != nullptr) {
      *outFileSizeBytes = queueEntry->fileSizeBytes;
    }
    if (outCacheState != nullptr) {
      *outCacheState = queueEntry->cacheState;
    }
    return queueEntry->fileHandle;
  }

  /**
   * Address: 0x00B1FEF0 (FUN_00B1FEF0)
   *
   * char *
   *
   * IDA signature:
   * int __cdecl sub_B1FEF0(char *a2);
   *
   * What it does:
   * Returns cached file handle for one path from the XEFIC queue cache lane.
   */
  HANDLE __cdecl wxFicGetCachedHandle(const char* const fileName)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(rootedFileName);
    if (queueEntry == nullptr) {
      return nullptr;
    }
    return queueEntry->fileHandle;
  }

  /**
   * Address: 0x00B1FF30 (FUN_00B1FF30)
   *
   * char *
   *
   * IDA signature:
   * int __cdecl sub_B1FF30(char *a2);
   *
   * What it does:
   * Returns cached file-size lane (`+0x04`) for one XEFIC queued entry
   * addressed by path, or `-1` when the entry is absent.
   */
  std::int32_t __cdecl wxFicGetCachedFileSizeBytes(const char* const fileName)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);

    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(rootedFileName);
    if (queueEntry == nullptr) {
      return -1;
    }
    return queueEntry->fileSizeBytes;
  }

  /**
   * Address: 0x00B1FF70 (FUN_00B1FF70)
   *
   * char *
   *
   * IDA signature:
   * int __cdecl sub_B1FF70(char *a2);
   *
   * What it does:
   * Returns cached state lane (`+0x08`) for one XEFIC queued entry addressed
   * by path, or `-1` when the entry is absent.
   */
  std::int32_t __cdecl wxFicGetCachedState(const char* const fileName)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);

    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(rootedFileName);
    if (queueEntry == nullptr) {
      return -1;
    }
    return queueEntry->cacheState;
  }

  /**
   * Address: 0x00B1FFB0 (FUN_00B1FFB0)
   *
   * char *, int
   *
   * IDA signature:
   * int __cdecl sub_B1FFB0(char *a2, int arg4);
   *
   * What it does:
   * Looks up one XEFIC queued entry by path and updates its cached state lane
   * (`+0x08`) when found.
   */
  XeficQueuedFileEntry* __cdecl wxFicSetCachedState(const char* const fileName, const std::int32_t cacheState)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);

    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(rootedFileName);
    if (queueEntry != nullptr) {
      queueEntry->cacheState = cacheState;
    }
    return queueEntry;
  }

  /**
   * Address: 0x00B1FFF0 (FUN_00B1FFF0)
   *
   * int, char *
   *
   * IDA signature:
   * void __cdecl sub_B1FFF0(int _10C, char *a2);
   *
   * What it does:
   * Disables one cached XEFIC file entry by path, closing any open file handle
   * and clearing the handle lane.
   */
  void __cdecl wxFicDisableFile([[maybe_unused]] const std::int32_t callbackContext, const char* const fileName)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);

    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(rootedFileName);

    if (queueEntry == nullptr) {
      std::sprintf(wxfic_cache_file, kXeficDisableFileMissingCacheEntryFormat, rootedFileName);
      xeci_error(0, wxfic_cache_file);
      return;
    }

    if (queueEntry->fileHandle != nullptr) {
      xefic_lock();
      xeci_save_thread_prio();
      CloseHandle(queueEntry->fileHandle);
      xeci_set_thread_prio();
      queueEntry->fileHandle = nullptr;
      xefic_unlock();
    }
  }

  /**
   * Address: 0x00B20080 (FUN_00B20080)
   *
   * int, char const *
   *
   * IDA signature:
   * void __cdecl sub_B20080(int _114, LPCSTR lpFileName);
   *
   * What it does:
   * Resolves one file path into XEFIC cache lane, opens the file when the
   * entry is unopened, and stores handle/size into the queued entry record.
   */
  void __cdecl wxFicEnableFile([[maybe_unused]] const std::int32_t callbackContext, LPCSTR fileName)
  {
    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);

    XeficQueuedFileEntry* const queueEntry = xefic_FindQueuedFileEntryByPathLocked(rootedFileName);

    if (queueEntry == nullptr) {
      std::sprintf(wxfic_cache_file, kXeficEnableFileMissingCacheEntryFormat, rootedFileName);
      xeci_error(0, wxfic_cache_file);
    }

    if (queueEntry->fileHandle == nullptr) {
      xefic_lock();
      xeci_save_thread_prio();

      HANDLE openedHandle = INVALID_HANDLE_VALUE;
      if (xeci_read_file_mode != 0) {
        openedHandle = CreateFileA(
          fileName,
          GENERIC_READ,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          nullptr,
          OPEN_EXISTING,
          0x10000000u,
          nullptr
        );
      } else {
        openedHandle = CreateFileA(
          fileName,
          GENERIC_READ,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          nullptr,
          OPEN_EXISTING,
          0x60000000u,
          nullptr
        );
      }

      xeci_set_thread_prio();
      if (openedHandle == INVALID_HANDLE_VALUE) {
        std::sprintf(wxfic_cache_file, kXeficEnableFileOpenErrorFormat, fileName);
        xeci_error(0, wxfic_cache_file);
      } else {
        const DWORD fileSize = GetFileSize(openedHandle, nullptr);
        queueEntry->fileHandle = openedHandle;
        queueEntry->fileSizeBytes = static_cast<std::int32_t>(fileSize);
        xefic_unlock();
      }
    }
  }

  /**
   * Address: 0x00B20190 (FUN_00B20190)
   *
   * struct_sofdec_xefic_obj *, int (__cdecl *)(int, int), int
   *
   * IDA signature:
   * void __cdecl sub_B20190(struct_sofdec_xefic_obj *a1, int (__cdecl *a2)(int, int), int a3);
   *
   * What it does:
   * Iterates one XEFIC object's queued entries and invokes one visitor callback
   * per entry until all entries are visited or callback returns `-1`.
   */
  void __cdecl xefic_ForEachQueuedEntryOnObjectUnlocked(
    XeficObject* const object,
    XeficQueueVisitor visitor,
    const std::int32_t contextValue
  )
  {
    const auto queuedEntryCount = xefic_GetQueuedEntryCount(object);
    object->queueCursor = object->queueHead;
    for (std::int32_t entryIndex = 0; entryIndex < queuedEntryCount; ++entryIndex) {
      XeficQueuedFileEntry* const queueEntry = xefic_obj_pop(object);
      if (visitor(queueEntry, contextValue) == -1) {
        break;
      }
    }
  }

  /**
   * Address: 0x00B20160 (FUN_00B20160)
   *
   * struct_sofdec_xefic_obj *, int (__cdecl *)(int, int), int
   *
   * IDA signature:
   * void __cdecl sub_B20160(struct_sofdec_xefic_obj *a1, int (__cdecl *a2)(int, int), int a3);
   *
   * What it does:
   * Locks XEFIC object lanes, runs one queued-entry visitor pass for a single
   * object, then unlocks.
   */
  void __cdecl
  xefic_ForEachQueuedEntryOnObjectLocked(XeficObject* const object, XeficQueueVisitor visitor, const std::int32_t contextValue)
  {
    xefic_lock();
    xefic_ForEachQueuedEntryOnObjectUnlocked(object, visitor, contextValue);
    xefic_unlock();
  }

  /**
   * Address: 0x00B20200 (sub_B20200)
   *
   * What it does:
   * Iterates queued entries on all active XEFIC objects and invokes one
   * visitor callback per queued entry until callback aborts with `-1`.
   */
  void xefic_ForEachQueuedEntryAcrossObjects(XeficQueueVisitor visitor, const std::int32_t contextValue)
  {
    for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
      if (object->used == 0) {
        continue;
      }

      const auto queuedEntryCount = xefic_GetQueuedEntryCount(object);
      object->queueCursor = object->queueHead;

      if (queuedEntryCount <= 0) {
        continue;
      }

      for (std::int32_t entryIndex = 0; entryIndex < queuedEntryCount; ++entryIndex) {
        XeficQueuedFileEntry* const queueEntry = xefic_obj_pop(object);
        if (visitor(queueEntry, contextValue) == -1) {
          return;
        }
      }
    }
  }

  /**
   * Address: 0x00B201E0 (FUN_00B201E0)
   *
   * int, int
   *
   * IDA signature:
   * void __cdecl sub_B201E0(int a1, int a2);
   *
   * What it does:
   * Locks XEFIC global critical section, visits queued entries on all active
   * objects, then unlocks.
   */
  void __cdecl xefic_ForEachQueuedEntryAcrossObjectsLocked(XeficQueueVisitor visitor, const std::int32_t contextValue)
  {
    xefic_lock();
    xefic_ForEachQueuedEntryAcrossObjects(visitor, contextValue);
    xefic_unlock();
  }

  /**
   * Address: 0x00B20260 (sub_B20260)
   *
   * What it does:
   * Locks XEFIC global critical section, dumps one object's queued entries to
   * debug output, then unlocks.
   */
  void xefic_DebugDumpQueueForObjectLocked(XeficObject* object)
  {
    xefic_lock();
    xefic_DebugDumpQueueForObjectUnlocked(object);
    xefic_unlock();
  }

  /**
   * Address: 0x00B20280 (sub_B20280)
   *
   * What it does:
   * Dumps one object's queued entry names and opened/closed status to debug
   * output.
   */
  void xefic_DebugDumpQueueForObjectUnlocked(XeficObject* object)
  {
    XeficDumpQueuedEntriesForObject(object);
  }

  /**
   * Address: 0x00B20310 (sub_B20310)
   *
   * What it does:
   * Locks XEFIC global critical section, dumps all objects' queued entries to
   * debug output, then unlocks.
   */
  void xefic_DebugDumpAllQueuesLocked()
  {
    xefic_lock();
    xefic_DebugDumpAllQueuesUnlocked();
    xefic_unlock();
  }

  /**
   * Address: 0x00B14710 (FUN_00B14710, sub_B14710)
   *
   * What it does:
   * Legacy thunk to global XEFIC queue debug dump.
   */
  [[maybe_unused]] void sofdec_DebugDumpAllQueuedEntriesThunk()
  {
    xefic_DebugDumpAllQueuesLocked();
  }

  /**
   * Address: 0x00B20320 (sub_B20320)
   *
   * What it does:
   * Dumps queued entry names/status for all active XEFIC objects to debug
   * output.
   */
  void xefic_DebugDumpAllQueuesUnlocked()
  {
    for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
      if (object->used == 0) {
        continue;
      }
      XeficDumpQueuedEntriesForObject(object);
    }
  }

  /**
   * Address: 0x00B203C0 (sub_B203C0)
   *
   * What it does:
   * Returns one XEFIC object state lane (`+0x04`).
   */
  std::int32_t xefic_GetObjectState(const XeficObject* object)
  {
    return object->state;
  }

  /**
   * Address: 0x00B145C0 (FUN_00B145C0, sub_B145C0)
   *
   * What it does:
   * Returns XEFIC object state when object is non-null; otherwise returns `-1`.
   */
  std::int32_t __cdecl ADXFIC_GetObjectState(const XeficObject* const object)
  {
    if (object == nullptr) {
      return -1;
    }
    return xefic_GetObjectState(object);
  }

  /**
   * Address: 0x00B203D0 (sub_B203D0)
   *
   * What it does:
   * Returns one XEFIC object state-signal lane (`+0x08`).
   */
  std::int32_t xefic_GetObjectStateSignal(const XeficObject* object)
  {
    return object->stateSignal;
  }

  /**
   * Address: 0x00B203E0 (sub_B203E0)
   *
   * What it does:
   * Clears state lanes when state-reset guard lane is active.
   */
  XeficObject* xefic_ResetObjectStateIfGuarded(XeficObject* object)
  {
    if (object->stateResetGuard != nullptr) {
      if (object->state == 6) {
        object->state = 0;
      }
      object->stateSignal = 0;
    }
    return object;
  }

  /**
   * Address: 0x00B1C040 (_m2asjd_default_callback)
   *
   * What it does:
   * Default M2ASJD error callback lane; reports success/no-op.
   */
  std::int32_t __cdecl m2asjd_default_callback(
    [[maybe_unused]] const std::int32_t callbackObject,
    [[maybe_unused]] const char* const errorMessage
  )
  {
    return 0;
  }

  /**
   * Address: 0x00B1BFD0 (_M2ASJD_SetCbErr)
   *
   * What it does:
   * Installs M2ASJD error callback lane; falls back to default callback when
   * caller provides null.
   */
  std::int32_t __cdecl M2ASJD_SetCbErr(M2asjdErrorCallback callback, const std::int32_t callbackObject)
  {
    if (callback != nullptr) {
      m2asjd_err_func = callback;
    } else {
      m2asjd_err_func = &m2asjd_default_callback;
    }
    m2asjd_err_obj = callbackObject;
    return 0;
  }

  /**
   * Address: 0x00B1C020 (_m2asjd_SetCbDcd)
   *
   * What it does:
   * Stores M2ASJD decode callback/object lanes used by decode server updates.
   */
  std::int32_t __cdecl m2asjd_SetCbDcd(M2asjdDecodeCallback decodeCallback, const std::int32_t callbackObject)
  {
    m2asjd_dcd_func = decodeCallback;
    m2asjd_dcd_obj = callbackObject;
    return 0;
  }

  /**
   * Address: 0x00B1C0C0 (_m2asjd_call_err_func)
   *
   * What it does:
   * Forwards one M2ASJD error message lane to the registered callback lane.
   */
  std::int32_t __cdecl m2asjd_call_err_func(const char* const errorMessage)
  {
    if (m2asjd_err_func != nullptr) {
      m2asjd_err_func(m2asjd_err_obj, errorMessage);
    }
    return 0;
  }

  /**
   * Address: 0x00B1B200 (FUN_00B1B200, _mpasjd_lock)
   *
   * What it does:
   * Enters the MPASJD decoder critical section lane.
   */
  void __cdecl mpasjd_lock()
  {
    EnterCriticalSection(&mpasjd_crs);
  }

  /**
   * Address: 0x00B1B210 (FUN_00B1B210, _mpasjd_unlock)
   *
   * What it does:
   * Leaves the MPASJD decoder critical section lane.
   */
  void __cdecl mpasjd_unlock()
  {
    LeaveCriticalSection(&mpasjd_crs);
  }

  /**
   * Address: 0x00B1B3C0 (_mpasjd_call_err_func)
   *
   * What it does:
   * Forwards one MPASJD error message lane to the registered callback.
   */
  std::int32_t __cdecl mpasjd_call_err_func(const char* const errorMessage)
  {
    if (mpasjd_err_func != nullptr) {
      mpasjd_err_func(mpasjd_err_obj, errorMessage);
    }
    return 0;
  }

  /**
   * Address: 0x00B1B150 (_MPASJD_SetCbErr)
   *
   * What it does:
   * Installs MPASJD error callback lane and forwards MPARBD errors through it.
   */
  std::int32_t __cdecl MPASJD_SetCbErr(const M2asjdErrorCallback callback, const std::int32_t callbackObject)
  {
    mpasjd_err_func = callback;
    mpasjd_err_obj = callbackObject;
    MPARBD_EntryErrFunc(reinterpret_cast<std::int32_t>(&mpasjd_call_err_func2), 0);
    return 0;
  }

  /**
   * Address: 0x00B1B180 (_MPASJD_SetCbDcd)
   *
   * What it does:
   * Stores MPASJD decode callback/object lanes consumed by exec updates.
   */
  std::int32_t __cdecl MPASJD_SetCbDcd(const MpasjdDecodeCallback decodeCallback, const std::int32_t callbackObject)
  {
    mpasjd_dcd_func = decodeCallback;
    mpasjd_dcd_obj = callbackObject;
    return 0;
  }

  /**
   * Address: 0x00B1B1A0 (_mpasjd_call_err_func2)
   *
   * What it does:
   * Adapts MPARBD error callback shape into MPASJD callback lane.
   */
  std::int32_t __cdecl mpasjd_call_err_func2(
    [[maybe_unused]] const char* const functionName,
    [[maybe_unused]] const std::int32_t sourceLine,
    const char* const errorMessage,
    const std::int32_t callbackObject
  )
  {
    if (mpasjd_err_func != nullptr) {
      mpasjd_err_func(callbackObject, errorMessage);
    }
    return 0;
  }

  /**
   * Address: 0x00B1B1C0 (_MPASJD_Init)
   *
   * What it does:
   * First-user startup for MPASJD runtime: bumps init refcount, initializes
   * lock, and runs MPARBD initialization under the lane lock.
   */
  std::int32_t __cdecl MPASJD_Init()
  {
    if (++mpasjd_init_count != 1) {
      return 0;
    }

    InitializeCriticalSection(&mpasjd_crs);
    mpasjd_lock();
    const std::int32_t result = mpasjd_Init();
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1B220 (_mpasjd_Init)
   *
   * What it does:
   * Initializes shared MPARBD runtime dependencies for MPASJD.
   */
  std::int32_t __cdecl mpasjd_Init()
  {
    MPARBD_Init();
    return 0;
  }

  /**
   * Address: 0x00B1B230 (_MPASJD_Finish)
   *
   * What it does:
   * Last-user MPASJD shutdown: finishes decoder lanes under lock then tears
   * down the MPASJD critical section.
   */
  std::int32_t __cdecl MPASJD_Finish()
  {
    if (--mpasjd_init_count != 0) {
      return 0;
    }

    mpasjd_lock();
    const std::int32_t result = mpasjd_Finish();
    mpasjd_unlock();
    DeleteCriticalSection(&mpasjd_crs);
    return result;
  }

  /**
   * Address: 0x00B1B270 (_mpasjd_Finish)
   *
   * What it does:
   * Destroys every active MPASJD handle then finalizes MPARBD runtime state.
   */
  std::int32_t __cdecl mpasjd_Finish()
  {
    while (mpasjd_entry != nullptr) {
      mpasjd_Destroy(mpasjd_entry);
    }
    MPARBD_Finish();
    return 0;
  }

  /**
   * Address: 0x00B1B2A0 (_MPASJD_Create)
   *
   * What it does:
   * Creates one MPASJD handle under the MPASJD lock lane.
   */
  std::int32_t __cdecl
  MPASJD_Create(MpasjdDecoderState* const decoderStorage, const std::int32_t storageBytes, MpasjdDecoderState** const outDecoder)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_Create(decoderStorage, storageBytes, outDecoder);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1B2D0 (_mpasjd_Create)
   *
   * What it does:
   * Initializes one MPASJD handle over caller-provided work memory and links it
   * into the active decoder list.
   */
  std::int32_t __cdecl
  mpasjd_Create(MpasjdDecoderState* const decoderStorage, const std::int32_t storageBytes, MpasjdDecoderState** const outDecoder)
  {
    if (decoderStorage == nullptr || outDecoder == nullptr) {
      mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }
    if (storageBytes < kMpasjdMinimumWorkBytes) {
      mpasjd_call_err_func(kM2asjdIllegalParameterMessage);
      return -2;
    }

    *outDecoder = nullptr;
    std::memset(decoderStorage, 0, sizeof(MpasjdDecoderState));
    mpasjd_Reset(decoderStorage);

    auto* const storageBase = reinterpret_cast<std::uint8_t*>(decoderStorage);
    decoderStorage->interleaveBuffer = reinterpret_cast<std::int8_t*>(storageBase + kMpasjdWorkBaseOffsetBytes);
    mpasjd_set_global_work(storageBase + kMpasjdReservedWorkBytes, storageBytes - kMpasjdReservedWorkBytes);

    MPARBD_SetUsrMallocFunc(reinterpret_cast<std::int32_t>(&mpasjd_malloc_func));
    MPARBD_SetUsrFreeFunc(reinterpret_cast<std::int32_t>(&mpasjd_free_func));

    MparbdDecoderState* decoderContext = nullptr;
    if (MPARBD_Create(&decoderContext) < 0) {
      return -1;
    }

    decoderStorage->heapManagerHandle = decoderStorage;
    decoderStorage->heapManagerOwner = storageBytes;
    decoderStorage->decoderContext = decoderContext;
    decoderStorage->slotState = 1;

    if (mpasjd_entry != nullptr) {
      mpasjd_entry->nextNewer = decoderStorage;
      decoderStorage->nextOlder = mpasjd_entry;
    }

    mpasjd_entry = decoderStorage;
    *outDecoder = decoderStorage;
    return 0;
  }

  /**
   * Address: 0x00B1B3E0 (_mpasjd_set_global_work)
   *
   * What it does:
   * Registers one temporary MPASJD allocation window used by MPARBD callbacks.
   */
  std::int32_t __cdecl mpasjd_set_global_work(std::uint8_t* const workBase, const std::int32_t workBytes)
  {
    mpasjd_global_work = workBase;
    mpasjd_global_wksize = workBytes;
    return 0;
  }

  /**
   * Address: 0x00B1B400 (_mpasjd_malloc_func)
   *
   * What it does:
   * Serves one linear allocation from MPASJD global work window.
   */
  std::int32_t __cdecl mpasjd_malloc_func(const std::uint32_t allocationBytes, void** const outAllocation)
  {
    *outAllocation = nullptr;

    if (mpasjd_global_work != nullptr && mpasjd_global_wksize >= static_cast<std::int32_t>(allocationBytes)) {
      *outAllocation = mpasjd_global_work;
      mpasjd_global_work += allocationBytes;
      mpasjd_global_wksize -= static_cast<std::int32_t>(allocationBytes);
      return 0;
    }

    mpasjd_call_err_func(kMpasjdWorkSizeTooSmallMessage);
    return -1;
  }

  /**
   * Address: 0x00B1B460 (_mpasjd_free_func)
   *
   * What it does:
   * No-op MPASJD allocator free hook (linear-work allocator lane).
   */
  std::int32_t __cdecl mpasjd_free_func()
  {
    return 0;
  }

  /**
   * Address: 0x00B1B470 (_MPASJD_Destroy)
   *
   * What it does:
   * Destroys one MPASJD handle under global MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_Destroy(MpasjdDecoderState* const decoder)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_Destroy(decoder);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1B490 (_mpasjd_Destroy)
   *
   * What it does:
   * Unlinks one MPASJD handle, destroys MPARBD context, and clears state.
   */
  std::int32_t __cdecl mpasjd_Destroy(MpasjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    MpasjdDecoderState* const nextNewer = decoder->nextNewer;
    MpasjdDecoderState* const nextOlder = decoder->nextOlder;
    if (nextNewer != nullptr) {
      nextNewer->nextOlder = nextOlder;
    } else {
      mpasjd_entry = nextOlder;
    }
    if (nextOlder != nullptr) {
      nextOlder->nextNewer = nextNewer;
    }

    MPARBD_Destroy(decoder->decoderContext);
    decoder->decoderContext = nullptr;
    std::memset(decoder, 0, sizeof(MpasjdDecoderState));
    return 0;
  }

  /**
   * Address: 0x00B1B4F0 (_MPASJD_Reset)
   *
   * What it does:
   * Resets one MPASJD handle under global lock.
   */
  std::int32_t __cdecl MPASJD_Reset(MpasjdDecoderState* const decoder)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_Reset(decoder);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1B510 (_mpasjd_Reset)
   *
   * What it does:
   * Resets decoded counters/flags and inner MPARBD lane for one MPASJD handle.
   */
  std::int32_t __cdecl mpasjd_Reset(MpasjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    if (decoder->decoderContext != nullptr) {
      MPARBD_Reset(decoder->decoderContext);
    }
    decoder->decodedByteCount = 0;
    decoder->decodedSampleCount = 0;
    decoder->termSupplyFlag = 0;
    return 0;
  }

  /**
   * Address: 0x00B1B950 (_MPASJD_Start)
   *
   * What it does:
   * Starts one MPASJD handle under global lock.
   */
  std::int32_t __cdecl MPASJD_Start(MpasjdDecoderState* const decoder)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_Start(decoder);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1B970 (_mpasjd_Start)
   *
   * What it does:
   * Primes MPASJD decode lane from stopped/flushed state.
   */
  std::int32_t __cdecl mpasjd_Start(MpasjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    if (decoder->runState == kMpasjdStateStopped || decoder->runState == kMpasjdStateFlushed) {
      mpasjd_Reset(decoder);
      MPARBD_SetEndStat(decoder->decoderContext, 0);
      decoder->runState = kMpasjdStatePrimed;
    }

    return 0;
  }

  /**
   * Address: 0x00B1B9C0 (_MPASJD_Stop)
   *
   * What it does:
   * Stops one MPASJD handle under global lock.
   */
  std::int32_t __cdecl MPASJD_Stop(MpasjdDecoderState* const decoder)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_Stop(decoder);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1B9E0 (_mpasjd_Stop)
   *
   * What it does:
   * Forces MPASJD run-state lane into stopped.
   */
  std::int32_t __cdecl mpasjd_Stop(MpasjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    decoder->runState = kMpasjdStateStopped;
    return 0;
  }

  /**
   * Address: 0x00B1BA10 (_MPASJD_GetStat)
   *
   * What it does:
   * Reads MPASJD run-state lane under global lock.
   */
  std::int32_t __cdecl MPASJD_GetStat(MpasjdDecoderState* const decoder, std::int32_t* const outStatus)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_GetStat(decoder, outStatus);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BA40 (_mpasjd_GetStat)
   *
   * What it does:
   * Returns current MPASJD run-state lane.
   */
  std::int32_t __cdecl mpasjd_GetStat(MpasjdDecoderState* const decoder, std::int32_t* const outStatus)
  {
    if (decoder != nullptr) {
      *outStatus = decoder->runState;
      return 0;
    }

    mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
    return -1;
  }

  /**
   * Address: 0x00B1BA70 (_MPASJD_GetNumChannels)
   *
   * What it does:
   * Reads decoded channel-count lane under MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_GetNumChannels(
    MpasjdDecoderState* const decoder,
    std::int32_t* const outChannelCount
  )
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_GetNumChannels(decoder, outChannelCount);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BAA0 (_mpasjd_GetNumChannels)
   *
   * What it does:
   * Queries channel-count lane from MPARBD decoder context.
   */
  std::int32_t __cdecl mpasjd_GetNumChannels(
    MpasjdDecoderState* const decoder,
    std::int32_t* const outChannelCount
  )
  {
    if (decoder != nullptr && outChannelCount != nullptr) {
      MPARBD_GetNumChannel(decoder->decoderContext, outChannelCount);
      return 0;
    }

    mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
    return -1;
  }

  /**
   * Address: 0x00B1BAE0 (_MPASJD_GetFrequency)
   *
   * What it does:
   * Reads decoded sample-rate lane under MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_GetFrequency(MpasjdDecoderState* const decoder, std::int32_t* const outSampleRate)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_GetFrequency(decoder, outSampleRate);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BB10 (_mpasjd_GetFrequency)
   *
   * What it does:
   * Queries sample-rate lane from MPARBD decoder context.
   */
  std::int32_t __cdecl mpasjd_GetFrequency(MpasjdDecoderState* const decoder, std::int32_t* const outSampleRate)
  {
    if (decoder != nullptr && outSampleRate != nullptr) {
      MPARBD_GetSfreq(decoder->decoderContext, outSampleRate);
      return 0;
    }

    mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
    return -1;
  }

  /**
   * Address: 0x00B1BB50 (_MPASJD_GetNumBits)
   *
   * What it does:
   * Reads decoded bits-per-sample lane under MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_GetNumBits(MpasjdDecoderState* const decoder, std::int32_t* const outBitsPerSample)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_GetNumBits(decoder, outBitsPerSample);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BB80 (_mpasjd_GetNumBits)
   *
   * What it does:
   * Queries bits-per-sample lane from MPARBD decoder context.
   */
  std::int32_t __cdecl mpasjd_GetNumBits(MpasjdDecoderState* const decoder, std::int32_t* const outBitsPerSample)
  {
    if (decoder != nullptr && outBitsPerSample != nullptr) {
      MPARBD_GetNumBit(decoder->decoderContext, outBitsPerSample);
      return 0;
    }

    mpasjd_call_err_func(kM2asjdGenericNullPointerMessage);
    return -1;
  }

  /**
   * Address: 0x00B1BBC0 (_MPASJD_GetNumSmplsDcd)
   *
   * What it does:
   * Reads decoded PCM sample count under MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_GetNumSmplsDcd(
    MpasjdDecoderState* const decoder,
    std::int32_t* const outSampleCount
  )
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_GetNumSmplsDcd(decoder, outSampleCount);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BBF0 (_mpasjd_GetNumSmplsDcd)
   *
   * What it does:
   * Converts MPARBD frame/block decoded counters into total decoded samples.
   */
  std::int32_t __cdecl mpasjd_GetNumSmplsDcd(
    MpasjdDecoderState* const decoder,
    std::int32_t* const outSampleCount
  )
  {
    if (decoder != nullptr && outSampleCount != nullptr) {
      std::int32_t decodedFrameCount = 0;
      std::int32_t decodedBlockCount = 0;
      MPARBD_GetNumSmplDcd(decoder->decoderContext, &decodedFrameCount, &decodedBlockCount);
      *outSampleCount = kMpasjdSamplesPerBlock * (decodedBlockCount + (decodedFrameCount * kMpasjdBlocksPerFrame));
      return 0;
    }

    mpasjd_call_err_func(kM2asjdGetNumSmplsDcdNullPointerMessage);
    return -1;
  }

  /**
   * Address: 0x00B1BC50 (_MPASJD_GetNumBytesDcd)
   *
   * What it does:
   * Reads decoded-byte count under MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_GetNumBytesDcd(
    MpasjdDecoderState* const decoder,
    std::int32_t* const outDecodedBytes
  )
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_GetNumBytesDcd(decoder, outDecodedBytes);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BC80 (_mpasjd_GetNumBytesDcd)
   *
   * What it does:
   * Queries decoded-byte count from inner MPARBD decoder lane.
   */
  std::int32_t __cdecl mpasjd_GetNumBytesDcd(
    MpasjdDecoderState* const decoder,
    std::int32_t* const outDecodedBytes
  )
  {
    if (decoder != nullptr && outDecodedBytes != nullptr) {
      MPARBD_GetNumByteDcd(decoder->decoderContext, outDecodedBytes);
      return 0;
    }

    mpasjd_call_err_func(kM2asjdGetNumBytesDcdNullPointerMessage);
    return -1;
  }

  /**
   * Address: 0x00B1BCC0 (_MPASJD_GetIoSj)
   *
   * What it does:
   * Returns source/output SJ lanes under MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_GetIoSj(
    MpasjdDecoderState* const decoder,
    M2asjdIoStream** const outSourceStream,
    std::int32_t* const outOutputStreamCount,
    M2asjdIoStream** const outOutputStreams
  )
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_GetIoSj(decoder, outSourceStream, outOutputStreamCount, outOutputStreams);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BCF0 (_mpasjd_GetIoSj)
   *
   * What it does:
   * Exposes MPASJD source and two output SJ lanes.
   */
  std::int32_t __cdecl mpasjd_GetIoSj(
    MpasjdDecoderState* const decoder,
    M2asjdIoStream** const outSourceStream,
    std::int32_t* const outOutputStreamCount,
    M2asjdIoStream** const outOutputStreams
  )
  {
    if (decoder == nullptr || outSourceStream == nullptr || outOutputStreamCount == nullptr || outOutputStreams == nullptr) {
      mpasjd_call_err_func(kMparbdNullPointerSentenceCaseMessage);
      return -1;
    }

    *outSourceStream = decoder->sourceStream;
    *outOutputStreamCount = 2;
    for (std::int32_t outputIndex = 0; outputIndex < *outOutputStreamCount; ++outputIndex) {
      outOutputStreams[outputIndex] = decoder->outputStreams[outputIndex];
    }
    return 0;
  }

  /**
   * Address: 0x00B1BD50 (_MPASJD_SetIoSj)
   *
   * What it does:
   * Updates source/output SJ lanes under MPASJD lock.
   */
  std::int32_t __cdecl MPASJD_SetIoSj(
    MpasjdDecoderState* const decoder,
    M2asjdIoStream* const sourceStream,
    const std::int32_t outputStreamCount,
    M2asjdIoStream** const outputStreams
  )
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_SetIoSj(decoder, sourceStream, outputStreamCount, outputStreams);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B1BD80 (_mpasjd_SetIoSj)
   *
   * What it does:
   * Stores source/output SJ lane pointers for MPASJD decode path.
   */
  std::int32_t __cdecl mpasjd_SetIoSj(
    MpasjdDecoderState* const decoder,
    M2asjdIoStream* const sourceStream,
    const std::int32_t outputStreamCount,
    M2asjdIoStream** const outputStreams
  )
  {
    if (decoder == nullptr || sourceStream == nullptr || outputStreams == nullptr) {
      mpasjd_call_err_func(kMparbdNullPointerSentenceCaseMessage);
      return -1;
    }
    if (outputStreamCount <= 0 || outputStreamCount > 2) {
      mpasjd_call_err_func(kM2asjdIllegalParameterMessage);
      return -2;
    }

    decoder->sourceStream = sourceStream;
    for (std::int32_t outputIndex = 0; outputIndex < outputStreamCount; ++outputIndex) {
      decoder->outputStreams[outputIndex] = outputStreams[outputIndex];
    }
    return 0;
  }

  /**
   * Address: 0x00B0F010 (FUN_00B0F010, _ADXT_DetachMpa)
   *
   * What it does:
   * Dispatches ADXT MPEG-audio detach through the installed link callback lane.
   */
  void adxt_detach_mpa(void* const adxtRuntime)
  {
    if (mpadetachfunc != nullptr) {
      (void)mpadetachfunc(adxtRuntime);
    }
  }

  /**
   * Address: 0x00B0F020 (FUN_00B0F020, _MPALINK_DetachMpa)
   *
   * What it does:
   * Detaches one MPASJD lane from ADXT runtime and tears down MPA callback lane.
   */
  std::int32_t __cdecl MPALINK_DetachMpa(AdxtRuntimeState* const adxtRuntime)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(adxtRuntime));

    auto* const decoder = AsAdxsjdRuntimeView(adxtRuntime->sjdHandle)->Decoder();
    auto* const mpaDecoder = static_cast<MpasjdDecoderState*>(decoder->mpegAudioDecoder);
    if (mpaDecoder != nullptr) {
      ADXT_Stop(adxtRuntime);
      MPASJD_Stop(mpaDecoder);
      MPASJD_Destroy(mpaDecoder);
      decoder->mpegAudioDecoder = nullptr;
      MPASJD_Finish();
      result = MPASJD_SetCbErr(nullptr, 0);
    }

    return result;
  }

  /**
   * Address: 0x00B0F070 (FUN_00B0F070, _MPALINK_StopMpa)
   *
   * What it does:
   * Stops one attached MPASJD decoder lane when ADXT runtime has MPA enabled.
   */
  std::int32_t __cdecl MPALINK_StopMpa(AdxtRuntimeState* const adxtRuntime)
  {
    auto* const mpaDecoder =
      static_cast<MpasjdDecoderState*>(AsAdxsjdRuntimeView(adxtRuntime->sjdHandle)->Decoder()->mpegAudioDecoder);
    if (mpaDecoder != nullptr) {
      return MPASJD_Stop(mpaDecoder);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(mpaDecoder));
  }

  /**
   * Address: 0x00B0F090 (FUN_00B0F090, _MPALINK_ExecOneMpa)
   *
   * What it does:
   * Executes one MPASJD decode step and mirrors decoded progress back to ADXB lanes.
   */
  std::int32_t __cdecl MPALINK_ExecOneMpa(moho::AdxBitstreamDecoderState* const decoder)
  {
    auto* const mpaDecoder = static_cast<MpasjdDecoderState*>(decoder->mpegAudioDecoder);
    std::int32_t mpaState = 0;
    MPASJD_GetStat(mpaDecoder, &mpaState);
    if (mpaState == 0) {
      decoder->decodeProgress0 = 0;
      decoder->entrySubmittedBytes = 0;
      MPASJD_Stop(mpaDecoder);
    }

    std::int32_t result = decoder->status;
    if (result == kMpasjdStatePrimed) {
      decoder->entrySubmittedBytes = 0;
      result = MPASJD_Start(mpaDecoder);
      decoder->status = kMpasjdStateRunning;
      return result;
    }

    if (result != kMpasjdStateRunning) {
      return result;
    }

    MPASJD_ExecHndl(mpaDecoder);

    std::int32_t frequency = 0;
    std::int32_t channelCount = 0;
    std::int32_t decodedSamples = 0;
    std::int32_t decodedBytes = 0;
    MPASJD_GetFrequency(mpaDecoder, &frequency);
    MPASJD_GetNumChannels(mpaDecoder, &channelCount);
    MPASJD_GetNumSmplsDcd(mpaDecoder, &decodedSamples);
    MPASJD_GetNumBytesDcd(mpaDecoder, &decodedBytes);

    const std::int32_t previousSubmittedBytes = decoder->entrySubmittedBytes;
    decoder->sourceChannels = static_cast<std::int8_t>(channelCount);
    decoder->sampleRate = frequency;
    decoder->decodeProgress0 = decodedSamples - previousSubmittedBytes;
    decoder->entrySubmittedBytes = previousSubmittedBytes + decoder->decodeProgress0;
    decoder->decodeProgress1 = decodedBytes;

    MPASJD_GetStat(mpaDecoder, &mpaState);
    result = mpaState;
    if (mpaState == kMpasjdStateFlushed) {
      MPASJD_Stop(mpaDecoder);
      decoder->status = 0;
      decoder->totalSampleCount = decodedSamples;
      result = decodedSamples;
    }

    return result;
  }

  /**
   * Address: 0x00B0F190 (FUN_00B0F190, _MPALINK_SetInSj)
   *
   * What it does:
   * Preserves current MPASJD output SJ lanes and applies caller input SJ lane.
   */
  std::int32_t __cdecl MPALINK_SetInSj(MpasjdDecoderState* const decoder, M2asjdIoStream* const sourceStream)
  {
    M2asjdIoStream* currentSourceStream = nullptr;
    std::int32_t outputStreamCount = 0;
    std::array<M2asjdIoStream*, 2> outputStreams{};

    MPASJD_GetIoSj(decoder, &currentSourceStream, &outputStreamCount, outputStreams.data());
    return MPASJD_SetIoSj(decoder, sourceStream, outputStreamCount, outputStreams.data());
  }

  /**
   * Address: 0x00B1BDF0 (_MPASJD_TermSupply)
   *
   * What it does:
   * Enables MPASJD terminate-supply lane under lock.
   */
  std::int32_t __cdecl MPASJD_TermSupply(MpasjdDecoderState* const decoder)
  {
    mpasjd_lock();
    const std::int32_t result = mpasjd_TermSupply(decoder);
    mpasjd_unlock();
    return result;
  }

  /**
   * Address: 0x00B0F1D0 (FUN_00B0F1D0, _MPALINK_TermSupply)
   *
   * What it does:
   * Link-layer thunk that forwards one MPA decoder terminate-supply request.
   */
  std::int32_t __cdecl MPALINK_TermSupply(MpasjdDecoderState* const decoder)
  {
    return MPASJD_TermSupply(decoder);
  }

  /**
   * Address: 0x00B0F1E0 (FUN_00B0F1E0, _MPALINK_CallErrFunc)
   *
   * What it does:
   * Forwards one MPA link-layer error message into ADXERR callback lane.
   */
  std::int32_t __cdecl MPALINK_CallErrFunc(const std::int32_t /*callbackObject*/, const char* const errorMessage)
  {
    ADXERR_CallErrFunc1_(errorMessage);
    return 0;
  }

  /**
   * Address: 0x00B1BE10 (_mpasjd_TermSupply)
   *
   * What it does:
   * Sets terminate-supply flag on MPASJD handle.
   */
  std::int32_t __cdecl mpasjd_TermSupply(MpasjdDecoderState* const decoder)
  {
    if (decoder != nullptr) {
      decoder->termSupplyFlag = 1;
      return 0;
    }

    mpasjd_call_err_func(kMparbdNullPointerSentenceCaseMessage);
    return -1;
  }

  /**
   * Address: 0x00B1B560 (_MPASJD_ExecServer)
   *
   * What it does:
   * Runs one MPASJD server tick under global lock.
   */
  std::int32_t __cdecl MPASJD_ExecServer()
  {
    mpasjd_lock();
    const std::int32_t execResult = mpasjd_ExecServer();
    mpasjd_unlock();
    return execResult;
  }

  /**
   * Address: 0x00B1B580 (_mpasjd_ExecServer)
   *
   * What it does:
   * Iterates active MPASJD handles from newest to older lane and executes each.
   */
  std::int32_t __cdecl mpasjd_ExecServer()
  {
    for (MpasjdDecoderState* decoder = mpasjd_entry; decoder != nullptr; decoder = decoder->nextOlder) {
      mpasjd_ExecHndl(decoder);
    }
    return 0;
  }

  /**
   * Address: 0x00B1B5A0 (_MPASJD_ExecHndl)
   *
   * What it does:
   * Runs one MPASJD handle step under global lock.
   */
  std::int32_t __cdecl MPASJD_ExecHndl(MpasjdDecoderState* const decoder)
  {
    mpasjd_lock();
    const std::int32_t execResult = mpasjd_ExecHndl(decoder);
    mpasjd_unlock();
    return execResult;
  }

  /**
   * Address: 0x00B1B5C0 (_mpasjd_ExecHndl)
   *
   * What it does:
   * Pulls source input into MPARBD, runs one decode step, updates counters,
   * notifies decode callback, emits PCM output, and transitions to flushed state.
   */
  std::int32_t __cdecl mpasjd_ExecHndl(MpasjdDecoderState* const decoder)
  {
    if (decoder->runState == kMpasjdStatePrimed) {
      decoder->runState = kMpasjdStateRunning;
    } else if (decoder->runState != kMpasjdStateRunning) {
      return 0;
    }

    mpasjd_input_proc(decoder);

    const std::int32_t previousDecodedBytes = decoder->decodedByteCount;
    const std::int32_t previousDecodedSamples = decoder->decodedSampleCount;

    MPARBD_ExecHndl(decoder->decoderContext);

    mpasjd_GetNumBytesDcd(decoder, &decoder->decodedByteCount);
    mpasjd_GetNumSmplsDcd(decoder, &decoder->decodedSampleCount);

    if (mpasjd_dcd_func != nullptr) {
      std::int32_t channelCount = 0;
      mpasjd_GetNumChannels(decoder, &channelCount);

      const std::int32_t consumedBytes = decoder->decodedByteCount - previousDecodedBytes;
      const std::int32_t producedSamples = decoder->decodedSampleCount - previousDecodedSamples;
      const std::int32_t producedBytes = 2 * channelCount * producedSamples;
      mpasjd_dcd_func(mpasjd_dcd_obj, decoder, consumedBytes, producedBytes);
    }

    mpasjd_output_proc(decoder);

    if (decoder->termSupplyFlag != 0) {
      if (decoder->sourceStream->QueryAvailableBytes(kM2asjdLaneSource) <= 0) {
        MPARBD_TermSupply(decoder->decoderContext);
      }

      std::int32_t decodeStatus = 0;
      MPARBD_GetDecStat(decoder->decoderContext, &decodeStatus);

      std::uint32_t remainingDataBytes = 0;
      MPARBF_GetDataSize(decoder->decoderContext->bitReaderHandlePrimary, &remainingDataBytes);
      if (decodeStatus == kMparbdStateNeedMoreData && remainingDataBytes < kMparbdMinimumFramePayloadBytes) {
        decoder->runState = kMpasjdStateFlushed;
      }
    }

    std::int32_t endStatus = 0;
    MPARBD_GetEndStat(decoder->decoderContext, &endStatus);
    if (endStatus == 1) {
      decoder->runState = kMpasjdStateFlushed;
    }
    return 0;
  }

  /**
   * Address: 0x00B1B700 (_mpasjd_input_proc)
   *
   * What it does:
   * Moves source SJ bytes into MPARBD primary bit-reader input lane.
   */
  std::int32_t __cdecl mpasjd_input_proc(MpasjdDecoderState* const decoder)
  {
    std::uint32_t freeBytes = 0;
    const std::int32_t primaryBitReaderHandle = decoder->decoderContext->bitReaderHandlePrimary;
    MPARBF_GetFreeSize(primaryBitReaderHandle, &freeBytes);
    if (freeBytes == 0) {
      return 0;
    }

    SjChunkRange sourceChunk{};
    decoder->sourceStream->AcquireChunk(kM2asjdLaneSource, static_cast<std::int32_t>(freeBytes), &sourceChunk);
    if (sourceChunk.byteCount <= 0) {
      decoder->sourceStream->ReturnChunk(kM2asjdLaneSource, &sourceChunk);
      return 0;
    }

    MPARBF_WriteData(
      primaryBitReaderHandle,
      sourceChunk.bufferAddress,
      static_cast<std::uint32_t>(sourceChunk.byteCount),
      nullptr
    );
    decoder->sourceStream->CommitChunk(kM2asjdLaneOutput, &sourceChunk);
    return 0;
  }

  /**
   * Address: 0x00B1B790 (_mpasjd_output_proc)
   *
   * What it does:
   * Reads interleaved MPARBD PCM bytes, de-interleaves into per-channel SJ
   * output chunks, and returns unread trailing MPARBD bytes.
   */
  std::int32_t __cdecl mpasjd_output_proc(MpasjdDecoderState* const decoder)
  {
    std::int32_t channelCount = 0;
    MPARBD_GetNumChannel(decoder->decoderContext, &channelCount);
    if (channelCount <= 0) {
      return 0;
    }
    if (channelCount > 2) {
      channelCount = 2;
    }

    std::array<M2asjdIoStream*, 2> outputStreams{decoder->outputStreams[0], decoder->outputStreams[1]};
    std::int32_t minimumAvailableBytes = outputStreams[0]->QueryAvailableBytes(kM2asjdLaneOutput);
    for (std::int32_t channelIndex = 1; channelIndex < channelCount; ++channelIndex) {
      const std::int32_t channelAvailableBytes = outputStreams[channelIndex]->QueryAvailableBytes(kM2asjdLaneOutput);
      if (minimumAvailableBytes > channelAvailableBytes) {
        minimumAvailableBytes = channelAvailableBytes;
      }
    }
    if (minimumAvailableBytes <= 0) {
      return 0;
    }

    std::uint32_t availableInterleavedBytes = 0;
    const std::int32_t secondaryBitReaderHandle = decoder->decoderContext->bitReaderHandleSecondary;
    MPARBF_GetDataSize(secondaryBitReaderHandle, &availableInterleavedBytes);
    if (availableInterleavedBytes == 0) {
      return 0;
    }

    const std::uint32_t maxRequestedInterleavedBytes = static_cast<std::uint32_t>(channelCount * minimumAvailableBytes);
    if (availableInterleavedBytes > maxRequestedInterleavedBytes) {
      availableInterleavedBytes = maxRequestedInterleavedBytes;
    }

    const std::uint32_t perChannelEvenBytes
      = (2u * (availableInterleavedBytes >> 1)) / static_cast<std::uint32_t>(channelCount);
    const std::uint32_t acquiredInterleavedBytes = perChannelEvenBytes * static_cast<std::uint32_t>(channelCount);

    std::array<SjChunkRange, 2> outputChunks{};
    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      outputStreams[channelIndex]->AcquireChunk(
        kM2asjdLaneOutput,
        static_cast<std::int32_t>(perChannelEvenBytes),
        &outputChunks[channelIndex]
      );
    }

    MPARBF_ReadData(
      secondaryBitReaderHandle,
      reinterpret_cast<char*>(decoder->interleaveBuffer),
      acquiredInterleavedBytes,
      nullptr
    );

    std::uint32_t writeSampleCount = static_cast<std::uint32_t>(outputChunks[0].byteCount) >> 1;
    for (std::int32_t channelIndex = 1; channelIndex < channelCount; ++channelIndex) {
      const auto channelSampleCount = static_cast<std::uint32_t>(outputChunks[channelIndex].byteCount) >> 1;
      if (writeSampleCount > channelSampleCount) {
        writeSampleCount = channelSampleCount;
      }
    }

    auto* interleavedPcm = reinterpret_cast<std::int16_t*>(decoder->interleaveBuffer);
    std::array<std::int16_t*, 2> outputPcmChannels{
      reinterpret_cast<std::int16_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(outputChunks[0].bufferAddress))),
      reinterpret_cast<std::int16_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(outputChunks[1].bufferAddress)))
    };
    for (std::uint32_t sampleIndex = 0; sampleIndex < writeSampleCount; ++sampleIndex) {
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        outputPcmChannels[channelIndex][sampleIndex] = *interleavedPcm++;
      }
    }

    const std::int32_t committedBytesPerChannel = static_cast<std::int32_t>(2 * writeSampleCount);
    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      SjChunkRange committedChunk{};
      SjChunkRange tailChunk{};
      SJ_SplitChunk(&outputChunks[channelIndex], committedBytesPerChannel, &committedChunk, &tailChunk);
      outputStreams[channelIndex]->CommitChunk(kM2asjdLaneSource, &committedChunk);
      outputStreams[channelIndex]->ReturnChunk(kM2asjdLaneOutput, &tailChunk);
    }

    const std::uint32_t consumedInterleavedBytes = static_cast<std::uint32_t>(2 * channelCount) * writeSampleCount;
    MPARBF_ReturnData(secondaryBitReaderHandle, acquiredInterleavedBytes - consumedInterleavedBytes, nullptr);
    return 0;
  }

  /**
   * Address: 0x00B1C050 (_m2asjd_lock)
   *
   * What it does:
   * Enters the M2ASJD decoder critical section and reports trapped failures.
   */
  std::int32_t __cdecl m2asjd_lock()
  {
#if defined(_MSC_VER)
    __try {
      EnterCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdEnterCriticalSectionFailedMessage);
    }
#else
    EnterCriticalSection(&m2asjd_crs);
#endif
    return 0;
  }

  /**
   * Address: 0x00B1C0E0 (_m2asjd_unlock)
   *
   * What it does:
   * Leaves the M2ASJD decoder critical section and reports trapped failures.
   */
  std::int32_t __cdecl m2asjd_unlock()
  {
#if defined(_MSC_VER)
    __try {
      LeaveCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdLeaveCriticalSectionFailedMessage);
    }
#else
    LeaveCriticalSection(&m2asjd_crs);
#endif
    return 0;
  }

  /**
   * Address: 0x00B1C1F0 (_m2asjd_Init)
   *
   * What it does:
   * Initializes the shared M2A decoder backend for the M2ASJD lane.
   */
  std::int32_t __cdecl m2asjd_Init()
  {
    M2ADEC_Initialize();
    return 0;
  }

  /**
   * Address: 0x00B1C150 (_M2ASJD_Init)
   *
   * What it does:
   * First-user startup for M2ASJD runtime: bumps init refcount, initializes
   * lock, then enters lane lock to run shared decoder initialization.
   */
  std::int32_t __cdecl M2ASJD_Init()
  {
    if (InterlockedIncrement(&m2asjd_init_count) != 1) {
      return 0;
    }

#if defined(_MSC_VER)
    __try {
      InitializeCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdInitializeCriticalSectionFailedMessage);
    }
#else
    InitializeCriticalSection(&m2asjd_crs);
#endif

    m2asjd_lock();
    const std::int32_t initResult = m2asjd_Init();
    m2asjd_unlock();
    return initResult;
  }

  /**
   * Address: 0x00B1C2A0 (_m2asjd_Finish)
   *
   * What it does:
   * Destroys all active M2ASJD decoder entries then finalizes shared M2A
   * decoder backend state.
   */
  std::int32_t __cdecl m2asjd_Finish()
  {
    while (m2asjd_entry != nullptr) {
      m2asjd_Destroy(m2asjd_entry);
    }
    M2ADEC_Finalize();
    return 0;
  }

  /**
   * Address: 0x00B1C200 (_M2ASJD_Finish)
   *
   * What it does:
   * Last-user shutdown for M2ASJD runtime: decrements init refcount, runs
   * decoder finish under lock, then deletes the critical section lane.
   */
  std::int32_t __cdecl M2ASJD_Finish()
  {
    if (InterlockedDecrement(&m2asjd_init_count) != 0) {
      return 0;
    }

    m2asjd_lock();
    const std::int32_t finishResult = m2asjd_Finish();
    m2asjd_unlock();

#if defined(_MSC_VER)
    __try {
      DeleteCriticalSection(&m2asjd_crs);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
      m2asjd_call_err_func(kM2asjdDeleteCriticalSectionFailedMessage);
    }
#else
    DeleteCriticalSection(&m2asjd_crs);
#endif

    return finishResult;
  }

  /**
   * Address: 0x00B1C000 (_M2ASJD_SetCbDcd)
   *
   * What it does:
   * Updates M2ASJD decode callback/object lanes under global M2ASJD lock.
   */
  std::int32_t __cdecl M2ASJD_SetCbDcd(
    const M2asjdDecodeCallback decodeCallback,
    const std::int32_t callbackObject
  )
  {
    m2asjd_lock();
    m2asjd_SetCbDcd(decodeCallback, callbackObject);
    m2asjd_unlock();
    return 0;
  }

  /**
   * Address: 0x00B1C2D0 (_M2ASJD_Create)
   *
   * What it does:
   * Creates one M2ASJD decoder handle under the global decoder lock.
   */
  std::int32_t __cdecl M2ASJD_Create(
    const std::int32_t heapManagerHandle,
    const std::int32_t heapManagerOwner,
    M2asjdDecoderState** const outDecoder
  )
  {
    m2asjd_lock();
    const std::int32_t createResult = m2asjd_Create(heapManagerHandle, heapManagerOwner, outDecoder);
    m2asjd_unlock();
    return createResult;
  }

  /**
   * Address: 0x00B1C460 (_M2ASJD_Destroy)
   *
   * What it does:
   * Destroys one M2ASJD decoder handle under the global decoder lock.
   */
  std::int32_t __cdecl M2ASJD_Destroy(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t destroyResult = m2asjd_Destroy(decoder);
    m2asjd_unlock();
    return destroyResult;
  }

  /**
   * Address: 0x00B1C300 (_m2asjd_Create)
   *
   * What it does:
   * Allocates one decoder lane and links it into the global active list.
   */
  std::int32_t __cdecl m2asjd_Create(
    const std::int32_t heapBufferAddress,
    const std::int32_t heapByteCount,
    M2asjdDecoderState** const outDecoder
  )
  {
    if (outDecoder == nullptr) {
      m2asjd_call_err_func(kM2asjdCreateNullPointerMessage);
      return -1;
    }

    *outDecoder = nullptr;

    void* heapManagerHandle = nullptr;
    if (heapBufferAddress != 0) {
      HEAPMNG_Create(
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(heapBufferAddress))),
        static_cast<std::uint32_t>(heapByteCount),
        &heapManagerHandle
      );
    }

    auto* const decoder =
      static_cast<M2asjdDecoderState*>(m2asjd_malloc(M2aPtrToWord(heapManagerHandle), 0x80u));
    if (decoder == nullptr) {
      return -1;
    }

    m2asjd_clear(decoder, sizeof(M2asjdDecoderState));
    m2asjd_Reset(decoder);

    decoder->stagingBuffer = static_cast<std::uint8_t*>(m2asjd_malloc(M2aPtrToWord(heapManagerHandle), 0x4000u));
    if (decoder->stagingBuffer == nullptr) {
      return -1;
    }

    decoder->stagingStream =
      reinterpret_cast<M2asjdIoStream*>(SJRBF_Create(M2aPtrToWord(decoder->stagingBuffer), 0x2000, 0x2000));
    if (decoder->stagingStream == nullptr) {
      m2asjd_free(M2aPtrToWord(heapManagerHandle), decoder->stagingBuffer);
      HEAPMNG_Destroy(heapManagerHandle);
      return -1;
    }

    M2aDecoderContext* decoderContext = nullptr;
    if (M2ADEC_Create(M2aPtrToWord(heapManagerHandle), &decoderContext) < 0) {
      ResolveM2asjdStreamDestroyFn(decoder->stagingStream)(decoder->stagingStream);
      m2asjd_free(M2aPtrToWord(heapManagerHandle), decoder->stagingBuffer);
      HEAPMNG_Destroy(heapManagerHandle);
      return -1;
    }

    decoder->heapManagerOwner = heapBufferAddress;
    decoder->heapManagerHandle = heapManagerHandle;
    decoder->ioContextValue = heapByteCount;
    decoder->slotState = 1;
    decoder->decoderContext = decoderContext;

    if (m2asjd_entry != nullptr) {
      m2asjd_entry->nextNewer = decoder;
      decoder->nextOlder = m2asjd_entry;
    }

    m2asjd_entry = decoder;
    *outDecoder = decoder;
    return 0;
  }

  /**
   * Address: 0x00B1C480 (_m2asjd_Destroy)
   *
   * What it does:
   * Unlinks one decoder and releases staging/decode resources for that lane.
   */
  std::int32_t __cdecl m2asjd_Destroy(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdDestroyNullPointerMessage);
      return -1;
    }

    M2asjdDecoderState* const nextNewer = decoder->nextNewer;
    M2asjdDecoderState* const nextOlder = decoder->nextOlder;
    if (nextNewer != nullptr) {
      nextNewer->nextOlder = nextOlder;
    } else {
      m2asjd_entry = nextOlder;
    }
    if (nextOlder != nullptr) {
      nextOlder->nextNewer = nextNewer;
    }

    void* const heapManagerHandle = decoder->heapManagerHandle;

    if (decoder->decoderContext != nullptr) {
      M2ADEC_Destroy(decoder->decoderContext);
      decoder->decoderContext = nullptr;
    }

    if (decoder->stagingStream != nullptr) {
      ResolveM2asjdStreamDestroyFn(decoder->stagingStream)(decoder->stagingStream);
      decoder->stagingStream = nullptr;
    }

    if (decoder->stagingBuffer != nullptr) {
      m2asjd_free(M2aPtrToWord(decoder->heapManagerHandle), decoder->stagingBuffer);
      decoder->stagingBuffer = nullptr;
    }

    if (heapManagerHandle != nullptr) {
      HEAPMNG_Destroy(heapManagerHandle);
    }

    m2asjd_clear(decoder, sizeof(M2asjdDecoderState));
    return 0;
  }

  /**
   * Address: 0x00B1C8D0 (_m2asjd_input_proc)
   *
   * What it does:
   * Moves one staged input chunk from source SJ lane into decoder staging lane.
   */
  std::int32_t __cdecl m2asjd_input_proc(M2asjdDecoderState* const decoder)
  {
    SjChunkRange sourceChunk{};
    decoder->sourceStream->AcquireChunk(kM2asjdLaneSource, 0x7FFFFFFF, &sourceChunk);

    if (sourceChunk.byteCount <= 0) {
      decoder->sourceStream->ReturnChunk(kM2asjdLaneSource, &sourceChunk);
      return 0;
    }

    SjChunkRange stagingChunk{};
    decoder->stagingStream->AcquireChunk(kM2asjdLaneOutput, sourceChunk.byteCount, &stagingChunk);
    if (stagingChunk.byteCount <= 0) {
      decoder->sourceStream->ReturnChunk(kM2asjdLaneSource, &sourceChunk);
      decoder->stagingStream->ReturnChunk(kM2asjdLaneOutput, &stagingChunk);
      return 0;
    }

    const std::int32_t copyBytes = (sourceChunk.byteCount < stagingChunk.byteCount) ? sourceChunk.byteCount : stagingChunk.byteCount;
    m2asjd_copy(
      reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(stagingChunk.bufferAddress))),
      reinterpret_cast<const void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sourceChunk.bufferAddress))),
      static_cast<std::uint32_t>(copyBytes)
    );

    SjChunkRange sourceTail{};
    SJ_SplitChunk(&sourceChunk, copyBytes, &sourceChunk, &sourceTail);
    decoder->sourceStream->ReturnChunk(kM2asjdLaneSource, &sourceTail);
    decoder->sourceStream->CommitChunk(kM2asjdLaneOutput, &sourceChunk);

    SjChunkRange stagingTail{};
    SJ_SplitChunk(&stagingChunk, copyBytes, &stagingChunk, &stagingTail);
    decoder->stagingStream->ReturnChunk(kM2asjdLaneOutput, &stagingTail);
    decoder->stagingStream->CommitChunk(kM2asjdLaneSource, &stagingChunk);
    return 0;
  }

  /**
   * Address: 0x00B1C9F0 (_m2asjd_output_proc)
   *
   * What it does:
   * Outputs one decoded frame to per-channel SJ output lanes without downmix.
   */
  std::int32_t __cdecl m2asjd_output_proc(M2asjdDecoderState* const decoder)
  {
    std::int32_t channelCount = 0;
    M2ADEC_GetNumChannels(decoder->decoderContext, &channelCount);
    if (channelCount == 0) {
      return 0;
    }

    std::array<SjChunkRange, kM2asjdSetIoMaxOutputStreams> outputChunks{};
    std::int32_t acquiredCount = 0;
    for (; acquiredCount < channelCount; ++acquiredCount) {
      decoder->outputStreams[acquiredCount]->AcquireChunk(kM2asjdLaneOutput, kM2asjdMinimumProcessBytes, &outputChunks[acquiredCount]);
      if (outputChunks[acquiredCount].byteCount < kM2asjdMinimumProcessBytes) {
        break;
      }
    }

    if (acquiredCount >= channelCount) {
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        M2ADEC_GetPcm(decoder->decoderContext, channelIndex, outputChunks[channelIndex].bufferAddress);
        decoder->outputStreams[channelIndex]->CommitChunk(kM2asjdLaneSource, &outputChunks[channelIndex]);
      }
      return 0;
    }

    for (std::int32_t rollbackIndex = acquiredCount; rollbackIndex >= 0; --rollbackIndex) {
      decoder->outputStreams[rollbackIndex]->ReturnChunk(kM2asjdLaneOutput, &outputChunks[rollbackIndex]);
    }
    return 0;
  }

  /**
   * Address: 0x00B1CAC0 (_m2asjd_output_stereo)
   *
   * What it does:
   * Outputs one decoded frame to up to two downmixed stereo lanes.
   */
  std::int32_t __cdecl m2asjd_output_stereo(M2asjdDecoderState* const decoder)
  {
    std::int32_t channelCount = 0;
    M2ADEC_GetNumChannels(decoder->decoderContext, &channelCount);
    if (channelCount == 0) {
      return 0;
    }

    if (channelCount > 2) {
      channelCount = 2;
    }

    std::array<SjChunkRange, kM2asjdSetIoMaxOutputStreams> outputChunks{};
    std::int32_t acquiredCount = 0;
    for (; acquiredCount < channelCount; ++acquiredCount) {
      decoder->outputStreams[acquiredCount]->AcquireChunk(kM2asjdLaneOutput, kM2asjdMinimumProcessBytes, &outputChunks[acquiredCount]);
      if (outputChunks[acquiredCount].byteCount < kM2asjdMinimumProcessBytes) {
        break;
      }
    }

    if (acquiredCount >= channelCount) {
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        M2ADEC_GetDownmixedPcm(decoder->decoderContext, channelIndex, outputChunks[channelIndex].bufferAddress);
        decoder->outputStreams[channelIndex]->CommitChunk(kM2asjdLaneSource, &outputChunks[channelIndex]);
      }
      return 0;
    }

    for (std::int32_t rollbackIndex = acquiredCount; rollbackIndex >= 0; --rollbackIndex) {
      decoder->outputStreams[rollbackIndex]->ReturnChunk(kM2asjdLaneOutput, &outputChunks[rollbackIndex]);
    }
    return 0;
  }

  /**
   * Address: 0x00B1CBA0 (_m2asjd_output_surround)
   *
   * What it does:
   * Outputs one decoded frame to up to two surround-mixed output lanes.
   */
  std::int32_t __cdecl m2asjd_output_surround(M2asjdDecoderState* const decoder)
  {
    std::int32_t channelCount = 0;
    M2ADEC_GetNumChannels(decoder->decoderContext, &channelCount);
    if (channelCount == 0) {
      return 0;
    }

    if (channelCount > 2) {
      channelCount = 2;
    }

    std::array<SjChunkRange, kM2asjdSetIoMaxOutputStreams> outputChunks{};
    std::int32_t acquiredCount = 0;
    for (; acquiredCount < channelCount; ++acquiredCount) {
      decoder->outputStreams[acquiredCount]->AcquireChunk(kM2asjdLaneOutput, kM2asjdMinimumProcessBytes, &outputChunks[acquiredCount]);
      if (outputChunks[acquiredCount].byteCount < kM2asjdMinimumProcessBytes) {
        break;
      }
    }

    if (acquiredCount >= channelCount) {
      for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
        M2ADEC_GetSurroundPcm(decoder->decoderContext, channelIndex, outputChunks[channelIndex].bufferAddress);
        decoder->outputStreams[channelIndex]->CommitChunk(kM2asjdLaneSource, &outputChunks[channelIndex]);
      }
      return 0;
    }

    for (std::int32_t rollbackIndex = acquiredCount; rollbackIndex >= 0; --rollbackIndex) {
      decoder->outputStreams[rollbackIndex]->ReturnChunk(kM2asjdLaneOutput, &outputChunks[rollbackIndex]);
    }
    return 0;
  }

  /**
   * Address: 0x00B1CC80 (_m2asjd_output_adx)
   *
   * What it does:
   * Outputs one decoded frame to ADX-lane routing (mono mirror or stereo pair).
   */
  std::int32_t __cdecl m2asjd_output_adx(M2asjdDecoderState* const decoder)
  {
    std::int32_t decodedChannelCount = 0;
    M2ADEC_GetNumChannels(decoder->decoderContext, &decodedChannelCount);
    if (decodedChannelCount == 0) {
      return 0;
    }

    std::int32_t downmixSourceLimit = 1;
    if (decodedChannelCount == 1) {
      decodedChannelCount = 1;
      downmixSourceLimit = 0;
    } else {
      decodedChannelCount = 2;
      downmixSourceLimit = 1;
    }

    std::array<SjChunkRange, kM2asjdSetIoMaxOutputStreams> outputChunks{};
    std::int32_t acquiredCount = 0;
    for (; acquiredCount < 2; ++acquiredCount) {
      if (decoder->outputStreams[acquiredCount] != nullptr) {
        decoder->outputStreams[acquiredCount]->AcquireChunk(
          kM2asjdLaneOutput,
          kM2asjdMinimumProcessBytes,
          &outputChunks[acquiredCount]
        );
        if (outputChunks[acquiredCount].byteCount < kM2asjdMinimumProcessBytes) {
          break;
        }
      }
    }

    if (acquiredCount >= 2) {
      for (std::int32_t outputLane = 0; outputLane < 2; ++outputLane) {
        if (decoder->outputStreams[outputLane] != nullptr) {
          const std::int32_t downmixSourceIndex = (outputLane < downmixSourceLimit) ? outputLane : downmixSourceLimit;
          M2ADEC_GetDownmixedPcm(decoder->decoderContext, downmixSourceIndex, outputChunks[outputLane].bufferAddress);
          decoder->outputStreams[outputLane]->CommitChunk(kM2asjdLaneSource, &outputChunks[outputLane]);
        }
      }
      return 0;
    }

    for (std::int32_t rollbackIndex = acquiredCount; rollbackIndex >= 0; --rollbackIndex) {
      decoder->outputStreams[rollbackIndex]->ReturnChunk(kM2asjdLaneOutput, &outputChunks[rollbackIndex]);
    }
    return 0;
  }

  /**
   * Address: 0x00B1C5F0 (_m2asjd_ExecHndl)
   *
   * What it does:
   * Executes one M2ASJD decode lane step: pulls staged input, runs M2A decode,
   * updates callback/state lanes, and dispatches output path by downmix mode.
   */
  std::int32_t __cdecl m2asjd_ExecHndl(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdNullDecoderHandleMessage);
      return -1;
    }

    if (decoder->runState != kM2asjdStatePrimed && decoder->runState != kM2asjdStateRunning) {
      return 0;
    }

    if (
      decoder->termSupplyFlag == kM2asjdTermSupplyEnabled
      && decoder->sourceStream->QueryAvailableBytes(kM2asjdLaneSource) < kM2asjdProcessWindowBytes
    ) {
      M2ADEC_BeginFlush(decoder->decoderContext);
    }

    if (decoder->runState == kM2asjdStatePrimed) {
      decoder->runState = kM2asjdStateRunning;
    }

    m2asjd_input_proc(decoder);

    SjChunkRange outputChunk{};
    decoder->outputStreams[0]->AcquireChunk(kM2asjdLaneOutput, kM2asjdProcessWindowBytes, &outputChunk);
    if (outputChunk.byteCount < kM2asjdMinimumProcessBytes) {
      decoder->outputStreams[0]->ReturnChunk(kM2asjdLaneOutput, &outputChunk);
      return 0;
    }
    decoder->outputStreams[0]->ReturnChunk(kM2asjdLaneOutput, &outputChunk);

    SjChunkRange inputChunk{};
    decoder->stagingStream->AcquireChunk(kM2asjdLaneSource, kM2asjdProcessWindowBytes, &inputChunk);
    if (
      decoder->termSupplyFlag != kM2asjdTermSupplyEnabled
      && inputChunk.byteCount < kM2asjdProcessWindowBytes
    ) {
      decoder->stagingStream->ReturnChunk(kM2asjdLaneSource, &inputChunk);
      return 0;
    }

    const std::int32_t previousDecodedSampleCount = decoder->decodedSampleCount;
    std::int32_t consumedInputBytes = 0;
    M2ADEC_Process(decoder->decoderContext, inputChunk.bufferAddress, inputChunk.byteCount, &consumedInputBytes);

    decoder->decodedByteCount += consumedInputBytes;
    M2ADEC_GetNumSamplesDecoded(decoder->decoderContext, &decoder->decodedSampleCount);

    if (m2asjd_dcd_func != nullptr) {
      std::int32_t decodedChannelCount = 0;
      M2ADEC_GetNumChannels(decoder->decoderContext, &decodedChannelCount);
      const std::int32_t producedSampleCount = decoder->decodedSampleCount - previousDecodedSampleCount;
      const std::int32_t producedByteCount = 2 * decodedChannelCount * producedSampleCount;
      m2asjd_dcd_func(m2asjd_dcd_obj, decoder, consumedInputBytes, producedByteCount);
    }

    SjChunkRange unreadChunk{};
    SJ_SplitChunk(&inputChunk, consumedInputBytes, &inputChunk, &unreadChunk);
    decoder->stagingStream->ReturnChunk(kM2asjdLaneSource, &unreadChunk);
    decoder->stagingStream->CommitChunk(kM2asjdLaneOutput, &inputChunk);

    std::int32_t decoderStatus = 0;
    M2ADEC_GetStatus(decoder->decoderContext, &decoderStatus);
    if (decoderStatus == kM2asjdDecoderStatusError) {
      std::int32_t decoderErrorCode = 0;
      M2ADEC_GetErrorCode(decoder->decoderContext, &decoderErrorCode);
      if (decoderErrorCode == kM2asjdDecoderErrorOutOfMemory) {
        m2asjd_call_err_func(kM2asjdAllocateDecoderMemoryMessage);
      } else if (decoderErrorCode == kM2asjdDecoderErrorAdifResume) {
        m2asjd_call_err_func(kM2asjdResumeAdifDecodeMessage);
      } else {
        m2asjd_call_err_func(kM2asjdUnknownDecoderErrorMessage);
      }
      decoder->runState = kM2asjdStateError;
      return -1;
    }

    M2ADEC_GetStatus(decoder->decoderContext, &decoderStatus);
    if (decoderStatus == kM2asjdDecoderStatusFlushed) {
      decoder->runState = kM2asjdStateFlushed;
    }

    std::int32_t decodedSampleCount = 0;
    M2ADEC_GetNumSamplesDecoded(decoder->decoderContext, &decodedSampleCount);
    if (decodedSampleCount == 0) {
      return 0;
    }

    std::int32_t decodedFrameCount = 0;
    M2ADEC_GetNumFramesDecoded(decoder->decoderContext, &decodedFrameCount);
    if (decoder->lastOutputFrameCount == decodedFrameCount) {
      return 0;
    }

    if (decoder->downmixMode == kM2asjdOutputModeStereo) {
      m2asjd_output_stereo(decoder);
    } else if (decoder->downmixMode == kM2asjdOutputModeSurround) {
      m2asjd_output_surround(decoder);
    } else if (decoder->downmixMode == kM2asjdOutputModeAdx) {
      m2asjd_output_adx(decoder);
    } else {
      m2asjd_output_proc(decoder);
    }

    decoder->lastOutputFrameCount = decodedFrameCount;
    return 0;
  }

  /**
   * Address: 0x00B1C5B0 (_m2asjd_ExecServer)
   *
   * What it does:
   * Iterates active M2ASJD decoder entries from newest to older lane and
   * executes one handle step per entry.
   */
  std::int32_t __cdecl m2asjd_ExecServer()
  {
    for (M2asjdDecoderState* decoder = m2asjd_entry; decoder != nullptr; decoder = decoder->nextOlder) {
      m2asjd_ExecHndl(decoder);
    }
    return 0;
  }

  /**
   * Address: 0x00B1C590 (_M2ASJD_ExecServer)
   *
   * What it does:
   * Runs one M2ASJD server tick under global lock and returns inner exec code.
   */
  std::int32_t __cdecl M2ASJD_ExecServer()
  {
    m2asjd_lock();
    const std::int32_t execResult = m2asjd_ExecServer();
    m2asjd_unlock();
    return execResult;
  }

  /**
   * Address: 0x00B1C5D0 (_M2ASJD_ExecHndl)
   *
   * What it does:
   * Runs one M2ASJD decoder handle step under global lock.
   */
  std::int32_t __cdecl M2ASJD_ExecHndl(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t execResult = m2asjd_ExecHndl(decoder);
    m2asjd_unlock();
    return execResult;
  }

  /**
   * Address: 0x00B1C520 (_M2ASJD_Reset)
   *
   * What it does:
   * Runs one M2ASJD decoder reset lane under the global decoder lock.
   */
  std::int32_t __cdecl M2ASJD_Reset(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t resetResult = m2asjd_Reset(decoder);
    m2asjd_unlock();
    return resetResult;
  }

  /**
   * Address: 0x00B1C540 (_m2asjd_Reset)
   *
   * What it does:
   * Resets one decoder lane state, including staged I/O reset and decode counters.
   */
  std::int32_t __cdecl m2asjd_Reset(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdResetNullPointerMessage);
      return -1;
    }

    if (decoder->decoderContext != nullptr) {
      M2ADEC_Reset(decoder->decoderContext);
    }

    if (decoder->stagingStream != nullptr) {
      decoder->stagingStream->Reset();
    }

    decoder->decodedByteCount = 0;
    decoder->decodedSampleCount = 0;
    decoder->lastOutputFrameCount = 0;
    decoder->termSupplyFlag = 0;
    return 0;
  }

  /**
   * Address: 0x00B1CD80 (_M2ASJD_Start)
   *
   * What it does:
   * Runs one decoder start lane under lock.
   */
  std::int32_t __cdecl M2ASJD_Start(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t startResult = m2asjd_Start(decoder);
    m2asjd_unlock();
    return startResult;
  }

  /**
   * Address: 0x00B1CDA0 (_m2asjd_Start)
   *
   * What it does:
   * Starts one decoder lane; if stopped/flushed it first resets runtime counters.
   */
  std::int32_t __cdecl m2asjd_Start(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdStartNullPointerMessage);
      return -1;
    }

    if (decoder->runState == 0 || decoder->runState == kM2asjdStateFlushed) {
      m2asjd_Reset(decoder);
      decoder->runState = kM2asjdStatePrimed;
    }

    M2ADEC_Start(decoder->decoderContext);
    return 0;
  }

  /**
   * Address: 0x00B1CDF0 (_M2ASJD_Stop)
   *
   * What it does:
   * Runs one decoder stop lane under lock.
   */
  std::int32_t __cdecl M2ASJD_Stop(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t stopResult = m2asjd_Stop(decoder);
    m2asjd_unlock();
    return stopResult;
  }

  /**
   * Address: 0x00B1CE10 (_m2asjd_Stop)
   *
   * What it does:
   * Stops one decoder lane and clears run-state lane.
   */
  std::int32_t __cdecl m2asjd_Stop(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdStopNullPointerMessage);
      return -1;
    }

    M2ADEC_Stop(decoder->decoderContext);
    decoder->runState = 0;
    return 0;
  }

  /**
   * Address: 0x00B1CE50 (_M2ASJD_GetStat)
   *
   * What it does:
   * Runs one status query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetStat(M2asjdDecoderState* const decoder, std::int32_t* const outStatus)
  {
    m2asjd_lock();
    const std::int32_t statusResult = m2asjd_GetStat(decoder, outStatus);
    m2asjd_unlock();
    return statusResult;
  }

  /**
   * Address: 0x00B1CE80 (_m2asjd_GetStat)
   *
   * What it does:
   * Returns current decoder run-state lane.
   */
  std::int32_t __cdecl m2asjd_GetStat(M2asjdDecoderState* const decoder, std::int32_t* const outStatus)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdGetStatusNullPointerMessage);
      return -1;
    }

    *outStatus = decoder->runState;
    return 0;
  }

  /**
   * Address: 0x00B1CEB0 (_M2ASJD_GetNumChannels)
   *
   * What it does:
   * Runs one channel-count query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumChannels(M2asjdDecoderState* const decoder, std::int32_t* const outChannelCount)
  {
    m2asjd_lock();
    const std::int32_t channelResult = m2asjd_GetNumChannels(decoder, outChannelCount);
    m2asjd_unlock();
    return channelResult;
  }

  /**
   * Address: 0x00B1CEE0 (_m2asjd_GetNumChannels)
   *
   * What it does:
   * Fetches decoded channel count from the M2A decoder context.
   */
  std::int32_t __cdecl m2asjd_GetNumChannels(M2asjdDecoderState* const decoder, std::int32_t* const outChannelCount)
  {
    if (decoder == nullptr || outChannelCount == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumChannelsNullPointerMessage);
      return -1;
    }

    M2ADEC_GetNumChannels(decoder->decoderContext, outChannelCount);
    return 0;
  }

  /**
   * Address: 0x00B1CF20 (_M2ASJD_GetChannelConfig)
   *
   * What it does:
   * Runs one channel-configuration query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetChannelConfig(
    M2asjdDecoderState* const decoder,
    std::int32_t* const outChannelConfiguration
  )
  {
    m2asjd_lock();
    const std::int32_t configurationResult = m2asjd_GetChannelConfig(decoder, outChannelConfiguration);
    m2asjd_unlock();
    return configurationResult;
  }

  /**
   * Address: 0x00B1CF50 (_m2asjd_GetChannelConfig)
   *
   * What it does:
   * Fetches decoded channel-configuration lane from the M2A context.
   */
  std::int32_t __cdecl m2asjd_GetChannelConfig(
    M2asjdDecoderState* const decoder,
    std::int32_t* const outChannelConfiguration
  )
  {
    if (decoder == nullptr || outChannelConfiguration == nullptr) {
      m2asjd_call_err_func(kM2asjdGetChannelConfigNullPointerMessage);
      return -1;
    }

    M2ADEC_GetChannelConfiguration(decoder->decoderContext, outChannelConfiguration);
    return 0;
  }

  /**
   * Address: 0x00B1CF90 (_M2ASJD_GetFrequency)
   *
   * What it does:
   * Runs one sampling-frequency query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetFrequency(M2asjdDecoderState* const decoder, std::int32_t* const outFrequency)
  {
    m2asjd_lock();
    const std::int32_t frequencyResult = m2asjd_GetFrequency(decoder, outFrequency);
    m2asjd_unlock();
    return frequencyResult;
  }

  /**
   * Address: 0x00B1CFC0 (_m2asjd_GetFrequency)
   *
   * What it does:
   * Fetches current decoder output frequency lane from M2A context.
   */
  std::int32_t __cdecl m2asjd_GetFrequency(M2asjdDecoderState* const decoder, std::int32_t* const outFrequency)
  {
    if (decoder == nullptr || outFrequency == nullptr) {
      m2asjd_call_err_func(kM2asjdGetFrequencyNullPointerMessage);
      return -1;
    }

    M2ADEC_GetFrequency(decoder->decoderContext, outFrequency);
    return 0;
  }

  /**
   * Address: 0x00B1D000 (_M2ASJD_GetNumBits)
   *
   * What it does:
   * Runs one output bit-depth query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumBits(M2asjdDecoderState* const decoder, std::int32_t* const outBitsPerSample)
  {
    m2asjd_lock();
    const std::int32_t bitResult = m2asjd_GetNumBits(decoder, outBitsPerSample);
    m2asjd_unlock();
    return bitResult;
  }

  /**
   * Address: 0x00B1D030 (_m2asjd_GetNumBits)
   *
   * What it does:
   * Returns fixed output PCM bit depth for M2ASJD decode lane.
   */
  std::int32_t __cdecl m2asjd_GetNumBits(M2asjdDecoderState* const decoder, std::int32_t* const outBitsPerSample)
  {
    if (decoder == nullptr || outBitsPerSample == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumBitsNullPointerMessage);
      return -1;
    }

    *outBitsPerSample = kM2asjdBitsPerSample;
    return 0;
  }

  /**
   * Address: 0x00B1D060 (_M2ASJD_GetNumSmplsDcd)
   *
   * What it does:
   * Runs one decoded-sample-count query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumSmplsDcd(M2asjdDecoderState* const decoder, std::int32_t* const outSampleCount)
  {
    m2asjd_lock();
    const std::int32_t sampleResult = m2asjd_GetNumSmplsDcd(decoder, outSampleCount);
    m2asjd_unlock();
    return sampleResult;
  }

  /**
   * Address: 0x00B1D090 (_m2asjd_GetNumSmplsDcd)
   *
   * What it does:
   * Fetches total decoded sample count from M2A context.
   */
  std::int32_t __cdecl m2asjd_GetNumSmplsDcd(M2asjdDecoderState* const decoder, std::int32_t* const outSampleCount)
  {
    if (decoder == nullptr || outSampleCount == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumSmplsDcdNullPointerMessage);
      return -1;
    }

    M2ADEC_GetNumSamplesDecoded(decoder->decoderContext, outSampleCount);
    return 0;
  }

  /**
   * Address: 0x00B1D0D0 (_M2ASJD_GetNumBytesDcd)
   *
   * What it does:
   * Runs one decoded-byte-count query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetNumBytesDcd(M2asjdDecoderState* const decoder, std::int32_t* const outDecodedBytes)
  {
    m2asjd_lock();
    const std::int32_t byteResult = m2asjd_GetNumBytesDcd(decoder, outDecodedBytes);
    m2asjd_unlock();
    return byteResult;
  }

  /**
   * Address: 0x00B1D100 (_m2asjd_GetNumBytesDcd)
   *
   * What it does:
   * Returns accumulated consumed-input byte count lane.
   */
  std::int32_t __cdecl m2asjd_GetNumBytesDcd(M2asjdDecoderState* const decoder, std::int32_t* const outDecodedBytes)
  {
    if (decoder == nullptr || outDecodedBytes == nullptr) {
      m2asjd_call_err_func(kM2asjdGetNumBytesDcdNullPointerMessage);
      return -1;
    }

    *outDecodedBytes = decoder->decodedByteCount;
    return 0;
  }

  /**
   * Address: 0x00B1D1C0 (_M2ASJD_GetDownmixMode)
   *
   * What it does:
   * Runs one downmix-mode query lane under lock.
   */
  std::int32_t __cdecl M2ASJD_GetDownmixMode(M2asjdDecoderState* const decoder, std::int32_t* const outDownmixMode)
  {
    m2asjd_lock();
    const std::int32_t downmixResult = m2asjd_GetDownmixMode(decoder, outDownmixMode);
    m2asjd_unlock();
    return downmixResult;
  }

  /**
   * Address: 0x00B1D1F0 (_m2asjd_GetDownmixMode)
   *
   * What it does:
   * Returns one decoder lane downmix-mode setting.
   */
  std::int32_t __cdecl m2asjd_GetDownmixMode(M2asjdDecoderState* const decoder, std::int32_t* const outDownmixMode)
  {
    if (decoder == nullptr || outDownmixMode == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    *outDownmixMode = decoder->downmixMode;
    return 0;
  }

  /**
   * Address: 0x00B1D2C0 (_M2ASJD_SetDownmixMode)
   *
   * What it does:
   * Runs one downmix-mode update lane under lock.
   */
  std::int32_t __cdecl M2ASJD_SetDownmixMode(M2asjdDecoderState* const decoder, const std::int32_t downmixMode)
  {
    m2asjd_lock();
    const std::int32_t setResult = m2asjd_SetDownmixMode(decoder, downmixMode);
    m2asjd_unlock();
    return setResult;
  }

  /**
   * Address: 0x00B1D2F0 (_m2asjd_SetDownmixMode)
   *
   * What it does:
   * Stores one decoder lane downmix-mode setting.
   */
  std::int32_t __cdecl m2asjd_SetDownmixMode(M2asjdDecoderState* const decoder, const std::int32_t downmixMode)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    decoder->downmixMode = downmixMode;
    return 0;
  }

  /**
   * Address: 0x00B1D320 (_M2ASJD_TermSupply)
   *
   * What it does:
   * Runs one term-supply toggle lane under lock.
   */
  std::int32_t __cdecl M2ASJD_TermSupply(M2asjdDecoderState* const decoder)
  {
    m2asjd_lock();
    const std::int32_t termResult = m2asjd_TermSupply(decoder);
    m2asjd_unlock();
    return termResult;
  }

  /**
   * Address: 0x00B0F2C0 (FUN_00B0F2C0, _ADXT_DetachMPEG2AAC)
   *
   * What it does:
   * Dispatches ADXT MPEG-2 AAC detach through the installed link callback lane.
   */
  void adxt_detach_m2a(void* const adxtRuntime)
  {
    if (m2adetachfunc != nullptr) {
      (void)m2adetachfunc(adxtRuntime);
    }
  }

  /**
   * Address: 0x00B0F2D0 (FUN_00B0F2D0, _M2ALINK_DetachM2a)
   *
   * What it does:
   * Detaches one M2ASJD lane from ADXT runtime and tears down M2A callback lane.
   */
  std::int32_t __cdecl M2ALINK_DetachM2a(AdxtRuntimeState* const adxtRuntime)
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(adxtRuntime));

    auto* const decoder = AsAdxsjdRuntimeView(adxtRuntime->sjdHandle)->Decoder();
    auto* const m2aDecoder = static_cast<M2asjdDecoderState*>(decoder->mpeg2AacDecoder);
    if (m2aDecoder != nullptr) {
      ADXT_Stop(adxtRuntime);
      M2ASJD_Stop(m2aDecoder);
      M2ASJD_Destroy(m2aDecoder);
      decoder->mpeg2AacDecoder = nullptr;
      M2ASJD_Finish();
      result = M2ASJD_SetCbErr(nullptr, 0);
    }

    return result;
  }

  /**
   * Address: 0x00B0F320 (FUN_00B0F320, _M2ALINK_StopM2a)
   *
   * What it does:
   * Stops one attached M2ASJD decoder lane when ADXT runtime has M2A enabled.
   */
  std::int32_t __cdecl M2ALINK_StopM2a(AdxtRuntimeState* const adxtRuntime)
  {
    auto* const m2aDecoder =
      static_cast<M2asjdDecoderState*>(AsAdxsjdRuntimeView(adxtRuntime->sjdHandle)->Decoder()->mpeg2AacDecoder);
    if (m2aDecoder != nullptr) {
      return M2ASJD_Stop(m2aDecoder);
    }
    return static_cast<std::int32_t>(reinterpret_cast<std::intptr_t>(m2aDecoder));
  }

  /**
   * Address: 0x00B0F340 (FUN_00B0F340, _M2ALINK_ExecOneM2a)
   *
   * What it does:
   * Executes one M2ASJD decode step and mirrors decoded progress back to ADXB lanes.
   */
  std::int32_t __cdecl M2ALINK_ExecOneM2a(moho::AdxBitstreamDecoderState* const decoder)
  {
    auto* const m2aDecoder = static_cast<M2asjdDecoderState*>(decoder->mpeg2AacDecoder);
    std::int32_t m2aState = 0;
    M2ASJD_GetStat(m2aDecoder, &m2aState);
    if (m2aState == 0) {
      decoder->decodeProgress0 = 0;
      decoder->entrySubmittedBytes = 0;
      M2ASJD_Stop(m2aDecoder);
    }

    std::int32_t result = decoder->status;
    if (result == kM2asjdStatePrimed) {
      decoder->entrySubmittedBytes = 0;
      result = M2ASJD_Start(m2aDecoder);
      decoder->status = kM2asjdStateRunning;
      return result;
    }

    if (result != kM2asjdStateRunning) {
      return result;
    }

    M2ASJD_ExecHndl(m2aDecoder);

    std::int32_t frequency = 0;
    std::int32_t channelCount = 0;
    std::int32_t decodedSamples = 0;
    std::int32_t decodedBytes = 0;
    M2ASJD_GetFrequency(m2aDecoder, &frequency);
    M2ASJD_GetNumChannels(m2aDecoder, &channelCount);
    M2ASJD_GetNumSmplsDcd(m2aDecoder, &decodedSamples);
    M2ASJD_GetNumBytesDcd(m2aDecoder, &decodedBytes);

    const std::int32_t previousSubmittedBytes = decoder->entrySubmittedBytes;
    decoder->sourceChannels = static_cast<std::int8_t>(channelCount);
    decoder->sampleRate = frequency;
    decoder->decodeProgress0 = decodedSamples - previousSubmittedBytes;
    decoder->entrySubmittedBytes = previousSubmittedBytes + decoder->decodeProgress0;
    decoder->decodeProgress1 = decodedBytes;

    M2ASJD_GetStat(m2aDecoder, &m2aState);
    result = m2aState;
    if (m2aState == kM2asjdStateFlushed) {
      M2ASJD_Stop(m2aDecoder);
      decoder->status = 0;
      decoder->totalSampleCount = decodedSamples;
      result = decodedSamples;
    }

    return result;
  }

  /**
   * Address: 0x00B0F440 (FUN_00B0F440, _M2ALINK_SetInSj)
   *
   * What it does:
   * Preserves current M2A output SJ lanes and applies caller input SJ lane.
   */
  std::int32_t __cdecl
  M2ALINK_SetInSj(M2asjdDecoderState* const decoder, M2asjdIoStream* const sourceStream)
  {
    M2asjdDecoderState* const decoderHandle = decoder;
    M2asjdIoStream* currentSourceStream = nullptr;
    std::int32_t outputStreamCount = 0;
    std::array<M2asjdIoStream*, kM2asjdGetIoReportedOutputStreams> outputStreams{};

    M2ASJD_GetIoSj(decoder, &currentSourceStream, &outputStreamCount, outputStreams.data());
    return M2ASJD_SetIoSj(decoderHandle, sourceStream, outputStreamCount, outputStreams.data());
  }

  /**
   * Address: 0x00B0F480 (FUN_00B0F480, _M2ALINK_TermSupply)
   *
   * What it does:
   * Link-layer thunk that forwards one M2A decoder terminate-supply request.
   */
  std::int32_t __cdecl M2ALINK_TermSupply(M2asjdDecoderState* const decoder)
  {
    return M2ASJD_TermSupply(decoder);
  }

  /**
   * Address: 0x00B0F490 (FUN_00B0F490, _M2ALINK_CallErrFunc)
   *
   * What it does:
   * Forwards one M2A link-layer error message into ADXERR callback lane.
   */
  std::int32_t __cdecl M2ALINK_CallErrFunc(const std::int32_t /*callbackObject*/, const char* const errorMessage)
  {
    ADXERR_CallErrFunc1_(errorMessage);
    return 0;
  }

  /**
   * Address: 0x00B1D340 (_m2asjd_TermSupply)
   *
   * What it does:
   * Enables end-of-supply flush mode for one decoder lane.
   */
  std::int32_t __cdecl m2asjd_TermSupply(M2asjdDecoderState* const decoder)
  {
    if (decoder == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    decoder->termSupplyFlag = kM2asjdTermSupplyEnabled;
    return 0;
  }

  /**
   * Address: 0x00B1D130 (FUN_00B1D130, _M2ASJD_GetIoSj)
   *
   * What it does:
   * Runs one M2ASJD IO-stream query lane under global decoder lock.
   */
  std::int32_t __cdecl M2ASJD_GetIoSj(
    M2asjdDecoderState* const decoder,
    M2asjdIoStream** const outSourceStream,
    std::int32_t* const outOutputStreamCount,
    M2asjdIoStream** const outOutputStreams
  )
  {
    m2asjd_lock();
    const std::int32_t getIoResult = m2asjd_GetIoSj(decoder, outSourceStream, outOutputStreamCount, outOutputStreams);
    m2asjd_unlock();
    return getIoResult;
  }

  /**
   * Address: 0x00B1D160 (FUN_00B1D160, _m2asjd_GetIoSj)
   *
   * What it does:
   * Returns source/output SJ stream lanes from one decoder lane.
   */
  std::int32_t __cdecl m2asjd_GetIoSj(
    M2asjdDecoderState* const decoder,
    M2asjdIoStream** const outSourceStream,
    std::int32_t* const outOutputStreamCount,
    M2asjdIoStream** const outOutputStreams
  )
  {
    if (decoder == nullptr || outSourceStream == nullptr || outOutputStreamCount == nullptr || outOutputStreams == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    *outSourceStream = decoder->sourceStream;
    *outOutputStreamCount = kM2asjdGetIoReportedOutputStreams;

    for (std::int32_t outputStreamIndex = 0; outputStreamIndex < *outOutputStreamCount; ++outputStreamIndex) {
      outOutputStreams[outputStreamIndex] = decoder->outputStreams[outputStreamIndex];
    }

    return 0;
  }

  /**
   * Address: 0x00B1D220 (FUN_00B1D220, _M2ASJD_SetIoSj)
   *
   * What it does:
   * Runs one M2ASJD IO-stream update lane under global decoder lock.
   */
  std::int32_t __cdecl M2ASJD_SetIoSj(
    M2asjdDecoderState* const decoder,
    M2asjdIoStream* const sourceStream,
    const std::int32_t outputStreamCount,
    M2asjdIoStream** const outputStreams
  )
  {
    m2asjd_lock();
    const std::int32_t setIoResult = m2asjd_SetIoSj(decoder, sourceStream, outputStreamCount, outputStreams);
    m2asjd_unlock();
    return setIoResult;
  }

  /**
   * Address: 0x00B1D250 (FUN_00B1D250, _m2asjd_SetIoSj)
   *
   * What it does:
   * Stores source/output SJ stream lanes for one decoder lane.
   */
  std::int32_t __cdecl m2asjd_SetIoSj(
    M2asjdDecoderState* const decoder,
    M2asjdIoStream* const sourceStream,
    const std::int32_t outputStreamCount,
    M2asjdIoStream** const outputStreams
  )
  {
    if (decoder == nullptr || sourceStream == nullptr || outputStreams == nullptr) {
      m2asjd_call_err_func(kM2asjdGenericNullPointerMessage);
      return -1;
    }

    if (outputStreamCount <= 0 || outputStreamCount > kM2asjdSetIoMaxOutputStreams) {
      m2asjd_call_err_func(kM2asjdIllegalParameterMessage);
      return -2;
    }

    decoder->sourceStream = sourceStream;
    for (std::int32_t outputStreamIndex = 0; outputStreamIndex < outputStreamCount; ++outputStreamIndex) {
      decoder->outputStreams[outputStreamIndex] = outputStreams[outputStreamIndex];
    }
    return 0;
  }

  /**
   * Address: 0x00B1D370 (FUN_00B1D370, _m2asjd_malloc)
   *
   * What it does:
   * Allocates one M2ASJD memory block via heap-manager lane or process heap.
   */
  void* __cdecl m2asjd_malloc(const std::int32_t heapManagerHandle, const SIZE_T byteCount)
  {
    if (heapManagerHandle != 0) {
      std::int32_t allocatedWord = heapManagerHandle;
      HEAPMNG_Allocate(heapManagerHandle, byteCount, &allocatedWord);
      return reinterpret_cast<void*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(allocatedWord)));
    }

    if (m2asjd_global_heap == nullptr) {
      m2asjd_global_heap = GetProcessHeap();
      if (m2asjd_global_heap == nullptr) {
        return nullptr;
      }
    }

    return HeapAlloc(m2asjd_global_heap, 8u, byteCount);
  }

  /**
   * Address: 0x00B1D3D0 (FUN_00B1D3D0, _m2asjd_free)
   *
   * What it does:
   * Frees one M2ASJD memory block through matching allocation backend.
   */
  void __cdecl m2asjd_free(const std::int32_t heapManagerHandle, LPVOID const memoryBlock)
  {
    if (heapManagerHandle != 0) {
      HEAPMNG_Free(heapManagerHandle, static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(memoryBlock)));
      return;
    }

    if (m2asjd_global_heap == nullptr) {
      m2asjd_global_heap = GetProcessHeap();
      if (m2asjd_global_heap == nullptr) {
        return;
      }
    }

    HeapFree(m2asjd_global_heap, 0, memoryBlock);
  }

  /**
   * Address: 0x00B1D420 (FUN_00B1D420, _m2asjd_clear)
   *
   * What it does:
   * Clears one M2ASJD byte range to zero.
   */
  std::int32_t __cdecl m2asjd_clear(void* const destinationBytes, const std::uint32_t byteCount)
  {
    std::memset(destinationBytes, 0, byteCount);
    return 0;
  }

  /**
   * Address: 0x00B1D440 (FUN_00B1D440, _m2asjd_copy)
   *
   * What it does:
   * Copies one byte range and returns copied byte count.
   */
  std::uint32_t __cdecl
  m2asjd_copy(void* const destinationBytes, const void* const sourceBytes, const std::uint32_t byteCount)
  {
    std::memcpy(destinationBytes, sourceBytes, byteCount);
    return byteCount;
  }

  /**
   * Address: 0x00B1D460 (FUN_00B1D460, _ADXSJE_GetVersion)
   *
   * What it does:
   * Returns packed ADXSJE encoder version lane (`0x0100`).
   */
  std::int16_t __cdecl ADXSJE_GetVersion()
  {
    return kAdxsjeVersion;
  }

  /**
   * Address: 0x00B1D470 (FUN_00B1D470, _ADXSJE_GetVerStr)
   *
   * What it does:
   * Returns static ADXSJE encoder version banner string lane.
   */
  char* __cdecl ADXSJE_GetVerStr()
  {
    return const_cast<char*>(kAdxsjeVersionString);
  }

  /**
   * Address: 0x00B1D480 (FUN_00B1D480, _adxsje_nsmpl_to_ofst)
   *
   * What it does:
   * Converts one encoded-sample count lane into ADX payload byte offset lane.
   */
  std::int32_t __cdecl
  adxsje_nsmpl_to_ofst(const std::int32_t channelCount, const std::int32_t headerInfoSizeBytes, const std::int32_t sampleCount)
  {
    return headerInfoSizeBytes + (18 * channelCount * ((sampleCount + 31) / 32)) + 4;
  }

  /**
   * Address: 0x00B1D4B0 (FUN_00B1D4B0, _ADXSJE_CalcLpInfo)
   *
   * What it does:
   * Computes loop padding, header byte size, and loop offsets for ADXSJE output.
   */
  std::int32_t __cdecl ADXSJE_CalcLpInfo(
    const std::int32_t channelCount,
    const std::int32_t currentSampleCount,
    const std::int32_t loopEndSampleCount,
    std::int32_t* const outHeaderInfoSizeBytes,
    std::int32_t* const outPaddedSampleCount,
    std::int32_t* const outLoopStartOffset,
    std::int32_t* const outLoopEndOffset
  )
  {
    const std::int32_t alignmentSamples = (channelCount == 1) ? 64 : 32;
    const std::int32_t paddedSampleCount = (alignmentSamples - (currentSampleCount % alignmentSamples)) % alignmentSamples;
    *outPaddedSampleCount = paddedSampleCount;

    const std::int32_t payloadBytes = 18 * channelCount * ((currentSampleCount + paddedSampleCount) / 32);
    const std::int32_t baseHeaderInfoSizeBytes = ADX_CalcHdrInfoLen(1, 0, 4, 4);
    const std::int32_t alignedHeaderPaddingBytes = (2048 - ((baseHeaderInfoSizeBytes + payloadBytes + 4) % 2048)) % 2048;
    *outHeaderInfoSizeBytes = baseHeaderInfoSizeBytes + alignedHeaderPaddingBytes;

    *outLoopStartOffset =
      adxsje_nsmpl_to_ofst(channelCount, *outHeaderInfoSizeBytes, currentSampleCount + *outPaddedSampleCount);
    *outLoopEndOffset = adxsje_nsmpl_to_ofst(channelCount, *outHeaderInfoSizeBytes, loopEndSampleCount + *outPaddedSampleCount);
    return *outLoopEndOffset;
  }

  /**
   * Address: 0x00B1D570 (FUN_00B1D570, _ADXSJE_GetInfo)
   *
   * What it does:
   * Decodes ADX header info and returns sample-bit/channel lane summary.
   */
  std::int32_t __cdecl ADXSJE_GetInfo(
    std::uint8_t* const sourceBytes,
    const std::int32_t sourceLength,
    std::int32_t* const outSampleBits,
    std::int32_t* const outChannels,
    std::int32_t* const outBlockSamples,
    std::int32_t* const outSampleRate
  )
  {
    std::int32_t headerIdentity = 0;
    std::int8_t headerType = 0;
    std::int8_t sampleBits = 0;
    std::int8_t channels = 0;
    std::int8_t blockBytes = 0;
    std::int32_t totalSamples = 0;

    const std::int32_t decodeResult = ADX_DecodeInfo(
      sourceBytes,
      sourceLength,
      &headerIdentity,
      &headerType,
      &sampleBits,
      &channels,
      &blockBytes,
      outBlockSamples,
      outSampleRate,
      &totalSamples
    );

    *outChannels = static_cast<std::int32_t>(channels);
    *outSampleBits = static_cast<std::int32_t>(sampleBits);
    return decodeResult;
  }

  /**
   * Address: 0x00B1D5D0 (FUN_00B1D5D0, _adxsje_write68)
   *
   * What it does:
   * Writes one element span to output SJ lane with endian swap for 16/32-bit
   * words.
   */
  std::int32_t __cdecl adxsje_write68(
    const void* const sourceBytes,
    const std::int32_t bytesPerElement,
    const std::int32_t elementCount,
    moho::SofdecSjSupplyHandle* const outputSjHandle
  )
  {
    SjChunkRange writableChunk{};
    const std::int32_t requestedBytes = bytesPerElement * elementCount;
    outputSjHandle->dispatchTable->getChunk(outputSjHandle, 0, requestedBytes, &writableChunk);
    if (writableChunk.byteCount < requestedBytes) {
      outputSjHandle->dispatchTable->putChunk(outputSjHandle, 0, &writableChunk);
      return 0;
    }

    auto* const destinationBytes = reinterpret_cast<std::uint8_t*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(writableChunk.bufferAddress))
    );
    const auto* const inputBytes = static_cast<const std::uint8_t*>(sourceBytes);

    switch (bytesPerElement) {
      case 4: {
        for (std::int32_t index = 0; index < elementCount; ++index) {
          std::uint32_t sourceWord = 0;
          std::memcpy(&sourceWord, inputBytes + (index * 4), sizeof(sourceWord));
          const std::uint32_t swappedWord =
            (sourceWord >> 24) | ((sourceWord >> 8) & 0x0000FF00u) | ((sourceWord << 8) & 0x00FF0000u) | (sourceWord << 24);
          std::memcpy(destinationBytes + (index * 4), &swappedWord, sizeof(swappedWord));
        }
        break;
      }
      case 2: {
        for (std::int32_t index = 0; index < elementCount; ++index) {
          std::uint16_t sourceHalfword = 0;
          std::memcpy(&sourceHalfword, inputBytes + (index * 2), sizeof(sourceHalfword));
          const std::uint16_t swappedHalfword = static_cast<std::uint16_t>((sourceHalfword >> 8) | (sourceHalfword << 8));
          std::memcpy(destinationBytes + (index * 2), &swappedHalfword, sizeof(swappedHalfword));
        }
        break;
      }
      case 1: {
        std::memcpy(destinationBytes, inputBytes, static_cast<std::uint16_t>(elementCount));
        break;
      }
      default: {
        while (true) {
        }
      }
    }

    outputSjHandle->dispatchTable->submitChunk(outputSjHandle, 1, &writableChunk);
    return elementCount;
  }

  /**
   * Address: 0x00B1D6D0 (FUN_00B1D6D0, _iirflt_init)
   *
   * What it does:
   * Clears full ADXSJE IIR filter state pool.
   */
  std::int32_t __cdecl iirflt_init()
  {
    std::memset(adxsje_prdflt_obj, 0, sizeof(adxsje_prdflt_obj));
    return 0;
  }

  /**
   * Address: 0x00B20400 (xefic_init_lock)
   *
   * What it does:
   * Initializes XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_init_lock()
  {
    XeficInvokeCriticalSectionApi(&InitializeCriticalSection, kInitializeCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B20470 (xefic_delete_lock)
   *
   * What it does:
   * Deletes XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_delete_lock()
  {
    XeficInvokeCriticalSectionApi(&DeleteCriticalSection, kDeleteCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B204E0 (xefic_lock)
   *
   * What it does:
   * Enters XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_lock()
  {
    XeficInvokeCriticalSectionApi(&EnterCriticalSection, kEnterCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B20550 (xefic_unlock)
   *
   * What it does:
   * Leaves XEFIC critical section and reports failure via XECI error lane.
   */
  void xefic_unlock()
  {
    XeficInvokeCriticalSectionApi(&LeaveCriticalSection, kLeaveCriticalSectionFailedMessage);
  }

  /**
   * Address: 0x00B10B30 (_xeci_assert)
   *
   * What it does:
   * Dispatches one XECI error callback lane when registered.
   */
  void __cdecl xeci_assert(const std::int32_t errorCode, const char* const errorMessage)
  {
    if (xeci_err_func != nullptr) {
      xeci_err_func(xeci_err_obj, errorMessage, errorCode);
    }
  }

  /**
   * Address: 0x00B10F10 (FUN_00B10F10, _xeCiEntryErrFunc)
   *
   * What it does:
   * Registers the global XECI error callback and callback object lanes.
   */
  XeciErrorCallback __cdecl xeCiEntryErrFunc(
    const XeciErrorCallback callbackFunction,
    const std::int32_t callbackObject
  )
  {
    xeci_err_func = callbackFunction;
    xeci_err_obj = callbackObject;
    return callbackFunction;
  }

  /**
   * Address: 0x00B10B50 (FUN_00B10B50)
   *
   * What it does:
   * Completes one overlapped XECI read callback lane, recording transferred
   * bytes and clearing pending-update state.
   */
  void __stdcall xeci_OnReadCompletionStatus(
    const std::int32_t errorCode,
    const std::int32_t bytesRead,
    OVERLAPPED* const overlapped
  )
  {
    (void)errorCode;
    XeciObject* const object = reinterpret_cast<XeciObject*>(overlapped->hEvent);
    if (bytesRead == 0) {
      xeci_assert(0, kXeciReadCompletionErrorMessage);
      object->state = static_cast<std::int8_t>(kXeciStateError);
    }

    object->transferSizeBytes = static_cast<std::uint32_t>(bytesRead);
    object->wantsUpdate = 0;
  }

  /**
   * Address: 0x00B11B50 (xeci_error)
   *
   * What it does:
   * Forwards one XECI error message through `xeci_assert`.
   */
  int __cdecl xeci_error(const std::int32_t callbackObject, const char* const errorMessage)
  {
    xeci_assert(callbackObject, errorMessage);
    return 0;
  }

  /**
   * Address: 0x00B11990 (FUN_00B11990, _xeci_GetFileSizeFromPath)
   *
   * What it does:
   * Queries one path file-size lane through Win32 find APIs under wxCi lock
   * and restores caller XECI lock depth on all exits.
   */
  std::uint64_t __cdecl xeci_GetFileSizeFromPath(const char* const fileName)
  {
    WIN32_FIND_DATAA findFileData{};
    const std::int32_t removedLockCount = xeci_lock_count();
    wxCiLock();
    const HANDLE findHandle = FindFirstFileA(fileName, &findFileData);
    wxCiUnLock();

    if (findHandle == INVALID_HANDLE_VALUE) {
      std::sprintf(wxfic_cache_file, kXeciGetFileSizeOpenErrorFormat, fileName);
      xeci_assert(0, wxfic_cache_file);
      xeci_lock_n(removedLockCount);
      return 0;
    }

    wxCiLock();
    FindClose(findHandle);
    wxCiUnLock();

    const std::uint64_t fileSize = (static_cast<std::uint64_t>(findFileData.nFileSizeHigh) << 32u)
      | static_cast<std::uint64_t>(findFileData.nFileSizeLow);
    xeci_lock_n(removedLockCount);
    return fileSize;
  }

  /**
   * Address: 0x00B10F30 (FUN_00B10F30)
   *
   * What it does:
   * Returns one file-size lane using optional XEFIC probe callback first, then
   * falls back to direct path query when the callback is absent or returns a
   * negative value.
   */
  std::int64_t __cdecl xeci_GetFileSizeResolved(const char* const fileName)
  {
    if (xeci_file_size_probe_callback != nullptr) {
      const std::int32_t callbackFileSize = xeci_file_size_probe_callback(fileName);
      if (callbackFileSize >= 0) {
        return static_cast<std::int64_t>(callbackFileSize);
      }
    }

    const std::int64_t fileSize = static_cast<std::int64_t>(xeci_GetFileSizeFromPath(fileName));
    if (fileSize < 0) {
      return kXeciInvalidFileSizeSentinel;
    }
    return fileSize;
  }

  /**
   * Address: 0x00B10F70 (FUN_00B10F70, _xeCiGetFileSize)
   *
   * What it does:
   * Resolves one XECI path against current root directory and returns the
   * low 32-bit file-size lane.
   */
  std::int32_t __cdecl xeCiGetFileSize(const char* const fileName)
  {
    if (fileName == nullptr) {
      xeci_assert(0, kXeciFileNameNullMessage);
      return 0;
    }

    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    return static_cast<std::int32_t>(xeci_GetFileSizeResolved(rootedFileName));
  }

  /**
   * Address: 0x00B10FC0 (FUN_00B10FC0, _xeCiOptionFunc)
   *
   * What it does:
   * Dispatches XECI option-query IDs to transfer-count and file-size accessors.
   */
  std::int32_t __cdecl xeCiOptionFunc(const void* const optionTarget, const std::int32_t optionCode)
  {
    switch (optionCode) {
    case 200:
      return static_cast<std::int32_t>(xeCiGetNumTrUpper(static_cast<const XeciObject*>(optionTarget)));
    case 201:
      return xeCiGetNumTrLower(static_cast<const XeciObject*>(optionTarget));
    case 202:
    case 204:
      return xeCiGetFileSizeUpper(static_cast<const XeciObject*>(optionTarget));
    case 203:
    case 205:
      return xeCiGetFileSizeLower(static_cast<const char*>(optionTarget));
    case 299:
      return 1;
    case 300:
      return static_cast<std::int32_t>(xeCiGetFileSizeByHndl(static_cast<const XeciObject*>(optionTarget)));
    default:
      return -1;
    }
  }

  /**
   * Address: 0x00B110F0 (FUN_00B110F0, xedir_new_handle)
   *
   * What it does:
   * Returns the first free XECI object lane in the fixed global object pool.
   */
  XeciObject* xedir_new_handle()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      if (xedir_work[objectIndex].used == 0) {
        return &xedir_work[objectIndex];
      }
    }
    return nullptr;
  }

  /**
   * Address: 0x00B111C0 (FUN_00B111C0, _xeCiOpen)
   *
   * What it does:
   * Allocates one XECI object, resolves file handle/size, and initializes
   * chunk geometry for subsequent read requests.
   */
  XeciObject* __cdecl xeCiOpen(const char* const fileName, const std::int32_t /*openMode*/, const std::int32_t readWriteFlag)
  {
    if (fileName == nullptr) {
      xeci_assert(0, kXeciOpenNullFileNameMessage);
      return nullptr;
    }
    if (readWriteFlag != 0) {
      xeci_assert(0, kXeciOpenInvalidRwMessage);
      return nullptr;
    }

    XeciObject* const object = xedir_new_handle();
    if (object == nullptr) {
      xeci_assert(0, kXeciOpenNoHandleMessage);
      return nullptr;
    }

    std::memset(object, 0, sizeof(XeciObject));

    char rootedFileName[MAX_PATH]{};
    xeDirAppendRootDir(rootedFileName, fileName);
    std::strcpy(object->fileName, rootedFileName);

    std::int32_t callbackFileSizeLow = 0;
    std::int32_t callbackFileSizeHighUnused = 0;
    HANDLE openedFile = nullptr;
    if (xeci_open_probe_callback != nullptr) {
      openedFile = xeci_open_probe_callback(rootedFileName, &callbackFileSizeLow, &callbackFileSizeHighUnused);
      if (openedFile != nullptr) {
        object->fileHandleOwnedExternally = 1;
      }
    }

    if (openedFile != nullptr) {
      object->fileHandle = openedFile;
      object->fileSizeLow = static_cast<std::uint32_t>(callbackFileSizeLow);
      object->fileSizeHigh = (callbackFileSizeLow < 0) ? -1 : 0;
    } else {
      object->fileHandle = nullptr;
      object->fileSizeLow = static_cast<std::uint32_t>(kXeciInvalidFileSizeSentinel);
      object->fileSizeHigh = static_cast<std::int32_t>(static_cast<std::uint64_t>(kXeciInvalidFileSizeSentinel) >> 32u);
    }

    (void)xeci_obj_init(object);
    if (object->fileHandle == nullptr) {
      object->fileHandle = xeci_create_func(object->fileName);
      if (object->fileHandle == nullptr) {
        object->state = static_cast<std::int8_t>(kXeciStateError);
        object->updateLockFlag = 0;
        xeci_obj_overlap_cleanup(object);
        return nullptr;
      }

      const std::uint64_t openedFileSize = xeUtyGetFileSizeEx(object->fileHandle);
      object->fileSizeLow = static_cast<std::uint32_t>(openedFileSize);
      object->fileSizeHigh = static_cast<std::int32_t>(openedFileSize >> 32u);

      const std::uint32_t chunkSize = object->readChunkSizeBytes;
      const std::uint64_t chunkCount = openedFileSize / static_cast<std::uint64_t>(chunkSize);
      object->transferChunkCount = static_cast<std::uint32_t>(chunkCount);
      if ((openedFileSize % static_cast<std::uint64_t>(chunkSize)) != 0u) {
        ++object->transferChunkCount;
      }
    }

    return object;
  }

  /**
   * Address: 0x00B11350 (FUN_00B11350, _xeCiClose)
   *
   * What it does:
   * Stops active transfer state and releases one XECI object lane according to
   * ownership/usage flags.
   */
  std::int32_t __cdecl xeCiClose(XeciObject* const object)
  {
    std::int32_t result = 0;
    if (object == nullptr) {
      return result;
    }

    xeCiStopTr(object);
    result = object->fileHandleOwnedExternally;
    if (result == 0) {
      xeci_obj_cleanup(object);
      return 0;
    }

    if (object->used == 1u) {
      object->used = 0;
      return xeci_obj_overlap_cleanup(object);
    }

    return result;
  }

  /**
   * Address: 0x00B11390 (FUN_00B11390, _xeCiSeek)
   *
   * What it does:
   * Updates one XECI chunk-cursor lane using absolute/current/end origin modes
   * and clamps it to `[0, transferChunkCount]`.
   */
  std::int32_t __cdecl xeCiSeek(XeciObject* const object, const std::int32_t offset, const std::int32_t originMode)
  {
    if (object == nullptr) {
      xeci_assert(0, kXeciNullHandleMessage);
      return 0;
    }

    xeci_lock();
    switch (originMode) {
    case 0:
      object->currentChunkIndex = offset;
      break;
    case 1:
      object->currentChunkIndex += offset;
      break;
    case 2:
      object->currentChunkIndex = static_cast<std::int32_t>(object->transferChunkCount) + offset;
      break;
    default:
      break;
    }

    const std::int32_t maxChunkIndex = static_cast<std::int32_t>(object->transferChunkCount);
    if (object->currentChunkIndex >= maxChunkIndex) {
      object->currentChunkIndex = maxChunkIndex;
    }
    if (object->currentChunkIndex <= 0) {
      object->currentChunkIndex = 0;
    }

    xeci_unlock();
    return object->currentChunkIndex;
  }

  /**
   * Address: 0x00B11410 (FUN_00B11410, _xeCiTell)
   *
   * What it does:
   * Returns one XECI chunk-cursor lane.
   */
  std::int32_t __cdecl xeCiTell(const XeciObject* const object)
  {
    if (object != nullptr) {
      return object->currentChunkIndex;
    }

    xeci_assert(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11430 (FUN_00B11430, nullsub_3621)
   *
   * What it does:
   * Legacy no-op callback lane retained for binary parity.
   */
  void xeci_LegacyNoOpCallback()
  {
  }

  /**
   * Address: 0x00B11440 (FUN_00B11440, _xeCiReqRead)
   *
   * What it does:
   * Queues one chunked XECI read request and validates read-size, seek, and
   * destination-buffer alignment constraints.
   */
  std::int32_t __cdecl xeCiReqRead(
    XeciObject* const object,
    std::int32_t requestedChunkCount,
    void* const readBuffer
  )
  {
    if (object == nullptr) {
      xeci_assert(0, kXeciNullHandleMessage);
      return 0;
    }
    if (requestedChunkCount < 0) {
      xeci_assert(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(object)), kXeciReqReadNegativeCountMessage);
      return 0;
    }
    if (requestedChunkCount == 0) {
      object->state = 1;
      return 0;
    }

    xeci_lock();
    if (xeci_has_active_transfer() == 1) {
      xeci_unlock();
      return 0;
    }

    if (
      object->fileSizeLow == static_cast<std::uint32_t>(kXeciInvalidFileSizeSentinel)
      && object->fileSizeHigh == static_cast<std::int32_t>(static_cast<std::uint64_t>(kXeciInvalidFileSizeSentinel) >> 32u)
    ) {
      const std::int64_t resolvedFileSize = xeci_GetFileSizeResolved(object->fileName);
      object->fileSizeLow = static_cast<std::uint32_t>(resolvedFileSize);
      object->fileSizeHigh = static_cast<std::int32_t>(static_cast<std::uint64_t>(resolvedFileSize) >> 32u);

      const std::int32_t chunkSize = static_cast<std::int32_t>(object->readChunkSizeBytes);
      const std::int64_t totalChunkCount = resolvedFileSize / chunkSize;
      object->transferChunkCount = static_cast<std::uint32_t>(totalChunkCount);
      if ((static_cast<std::uint64_t>(resolvedFileSize) % static_cast<std::uint64_t>(chunkSize)) != 0u) {
        ++object->transferChunkCount;
      }
    }

    if (
      object->fileSizeLow == static_cast<std::uint32_t>(kXeciInvalidFileSizeSentinel)
      && object->fileSizeHigh == static_cast<std::int32_t>(static_cast<std::uint64_t>(kXeciInvalidFileSizeSentinel) >> 32u)
    ) {
      requestedChunkCount = 0;
    }

    object->transferCountLow = 0;
    object->transferCountHigh = 0;
    object->readBufferPtr = readBuffer;

    const std::int32_t remainingChunkCount = static_cast<std::int32_t>(object->transferChunkCount) - object->currentChunkIndex;
    std::int32_t transferChunkCount = (requestedChunkCount < remainingChunkCount) ? requestedChunkCount : remainingChunkCount;
    object->readChunkCount = transferChunkCount;
    if (transferChunkCount >= 0x200) {
      transferChunkCount = 0x200;
    }
    object->readChunkCount = transferChunkCount;

    const std::int64_t readOffsetBytes =
      static_cast<std::int64_t>(object->readChunkSizeBytes) * static_cast<std::int64_t>(object->currentChunkIndex);
    const std::int32_t transferSizeBytes = transferChunkCount * static_cast<std::int32_t>(object->readChunkSizeBytes);
    if (transferSizeBytes == 0) {
      if (object->state != kXeciStateError) {
        object->state = 1;
      }
      xeci_unlock();
      return 0;
    }

    object->readOffsetLow = static_cast<std::int32_t>(readOffsetBytes);
    object->readOffsetHigh = static_cast<std::int32_t>(static_cast<std::uint64_t>(readOffsetBytes) >> 32u);
    object->transferSizeBytes = static_cast<std::uint32_t>(transferSizeBytes);
    object->state = static_cast<std::int8_t>(kXeciStateTransferring);
    object->wantsRead = 1;
    object->wantsUpdate = 0;
    xeci_unlock();

    if (xeci_read_file_mode == 0) {
      if ((transferSizeBytes < 0) || ((transferSizeBytes % 0x800) != 0)) {
        xeci_assert(0, kXeciReqReadIllegalSizeMessage);
        return 0;
      }
      if ((static_cast<std::uint64_t>(readOffsetBytes) % 0x800u) != 0u) {
        xeci_assert(0, kXeciReqReadIllegalSeekMessage);
        return 0;
      }
      if ((reinterpret_cast<std::uintptr_t>(readBuffer) & 3u) != 0u) {
        xeci_assert(0, kXeciReqReadIllegalBufferAlignmentMessage);
        return 0;
      }
    }

    if (readBuffer != nullptr) {
      return object->readChunkCount;
    }
    xeci_assert(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(object)), kXeciReqReadNullBufferMessage);
    return 0;
  }

  /**
   * Address: 0x00B11720 (FUN_00B11720, _xeCiGetStat)
   *
   * What it does:
   * Returns one signed XECI state-byte lane.
   */
  std::int32_t __cdecl xeCiGetStat(const XeciObject* const object)
  {
    if (object != nullptr) {
      return static_cast<std::int32_t>(object->state);
    }

    xeci_assert(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11770 (FUN_00B11770, _xeCiGetSctLen)
   *
   * What it does:
   * Returns current XECI chunk-size lane.
   */
  std::int32_t __cdecl xeCiGetSctLen(const XeciObject* const object)
  {
    if (object != nullptr) {
      return static_cast<std::int32_t>(object->readChunkSizeBytes);
    }

    xeci_assert(0, kXeciGetSctLenNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11740 (FUN_00B11740, xeci_more_work)
   *
   * What it does:
   * Scans the XECI object pool and returns `1` when any active object still has
   * pending update work.
   */
  std::int32_t xeci_more_work()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      const XeciObject& object = xedir_work[objectIndex];
      if (object.used != 0 && object.wantsUpdate == 1) {
        return 1;
      }
    }
    return 0;
  }

  /**
   * Address: 0x00B13D10 (FUN_00B13D10, j_xeci_more_work)
   *
   * What it does:
   * Thunk alias that forwards to `xeci_more_work`.
   */
  std::int32_t xeci_more_workThunk()
  {
    return xeci_more_work();
  }

  /**
   * Address: 0x00B13660 (FUN_00B13660, _mfCiGetInterface)
   *
   * What it does:
   * Returns the static MFCI CVFS-device interface table.
   */
  void* mfCiGetInterface()
  {
    return &mfci_vtbl;
  }

  /**
   * Address: 0x00B10900 (FUN_00B10900, _xeCiGetInterface)
   *
   * What it does:
   * Returns the static XECI CVFS-device interface table.
   */
  void* xeCiGetInterface()
  {
    xeci_vtbl.execServer = reinterpret_cast<CvFsNoArgOperationFn>(&xeCiExecServer);
    xeci_vtbl.registerUserErrorBridge = reinterpret_cast<CvFsRegisterUserErrorFn>(&xeCiEntryErrFunc);
    xeci_vtbl.openFile = reinterpret_cast<CvFsDeviceOpenFn>(&xeCiOpen);
    xeci_vtbl.closeFile = reinterpret_cast<CvFsCloseBridgeFn>(&xeCiClose);
    xeci_vtbl.seekFile = reinterpret_cast<CvFsSeekBridgeFn>(&xeCiSeek);
    xeci_vtbl.tellPosition = reinterpret_cast<CvFsHandleOperationFn>(&xeCiTell);
    xeci_vtbl.requestRead = reinterpret_cast<CvFsHandleReadWriteFn>(&xeCiReqRead);
    xeci_vtbl.requestWrite = reinterpret_cast<CvFsHandleReadWriteFn>(&xeci_LegacyNoOpCallback);
    xeci_vtbl.stopTransfer = reinterpret_cast<CvFsHandleOperationFn>(&xeCiStopTr);
    xeci_vtbl.getStat = reinterpret_cast<CvFsGetStatBridgeFn>(&xeCiGetStat);
    xeci_vtbl.getSectorLength = reinterpret_cast<CvFsHandleOperationFn>(&xeCiGetSctLen);
    xeci_vtbl.getTransferCount = reinterpret_cast<CvFsHandleOperationFn>(&xeCiGetNumTr);
    xeci_vtbl.getFileSizeEx = reinterpret_cast<CvFsPathArgOperationFn>(&xeCiGetFileSize);
    xeci_vtbl.option = reinterpret_cast<CvFsDeviceOptionFn>(&xeCiOptionFunc);
    return &xeci_vtbl;
  }

  /**
   * Address: 0x00B13670 (FUN_00B13670, _mfci_call_errfn)
   *
   * What it does:
   * Forwards one MFCI error message to the registered user callback.
   */
  std::int32_t __cdecl mfci_call_errfn(const std::int32_t callbackObject, const char* const errorMessage)
  {
    (void)callbackObject;
    if (mfci_err_func != nullptr) {
      mfci_err_func(mfci_err_obj, errorMessage);
    }
    return 0;
  }

  /**
   * Address: 0x00B13690 (FUN_00B13690, _mfci_strtoul)
   *
   * What it does:
   * Thin thunk around `strtoul` for MFCI address parser code paths.
   */
  std::uint32_t __cdecl mfci_strtoul(const char* const text, const char** const outNextText, const std::int32_t base)
  {
    char* nextText = nullptr;
    const std::uint32_t parsedValue = static_cast<std::uint32_t>(std::strtoul(text, &nextText, base));
    if (outNextText != nullptr) {
      *outNextText = nextText;
    }
    return parsedValue;
  }

  /**
   * Address: 0x00B136A0 (FUN_00B136A0, _mfci_get_adr_size)
   *
   * What it does:
   * Parses `ADDR.SIZE` text into `ADDR` return value and optional `SIZE`.
   */
  std::uint32_t __cdecl mfci_get_adr_size(const char* const addressAndSizeText, std::uint32_t* const outSizeBytes)
  {
    if (std::strlen(addressAndSizeText) != 17u) {
      std::sprintf(mfci_err_str, kMfciGetAdrSizeInvalidLengthFormat, addressAndSizeText);
      (void)mfci_call_errfn(0, mfci_err_str);
    }

    if (addressAndSizeText[8] != '.') {
      std::sprintf(mfci_err_str, kMfciGetAdrSizeInvalidFormat, addressAndSizeText);
      (void)mfci_call_errfn(0, mfci_err_str);
    }

    const char* parseCursor = addressAndSizeText;
    const std::uint32_t addressValue = mfci_strtoul(addressAndSizeText, &parseCursor, 16);

    const char* sizeCursor = parseCursor;
    if (*sizeCursor != '\0') {
      ++sizeCursor;
    }

    if (outSizeBytes != nullptr) {
      *outSizeBytes = mfci_strtoul(sizeCursor, &parseCursor, 16);
    }

    return addressValue;
  }

  /**
   * Address: 0x00B13740 (FUN_00B13740, _mfCiExecHndl)
   *
   * What it does:
   * Legacy MFCI handle tick is a no-op on this runtime lane.
   */
  void mfCiExecHndl()
  {
  }

  /**
   * Address: 0x00B13750 (FUN_00B13750, _mfCiExecServer)
   *
   * What it does:
   * Legacy MFCI server tick is a no-op on this runtime lane.
   */
  void mfCiExecServer()
  {
  }

  /**
   * Address: 0x00B13760 (FUN_00B13760, _mfCiEntryErrFunc)
   *
   * What it does:
   * Registers the MFCI user error callback pair and returns the callback.
   */
  CvFsUserErrorBridgeFn __cdecl mfCiEntryErrFunc(
    const CvFsUserErrorBridgeFn callbackFunction,
    const std::int32_t callbackObject
  )
  {
    mfci_err_func = callbackFunction;
    mfci_err_obj = callbackObject;
    return callbackFunction;
  }

  /**
   * Address: 0x00B13780 (FUN_00B13780, _mfCiGetFileSize)
   *
   * What it does:
   * Parses `ADDR.SIZE` text and returns the `SIZE` lane in bytes.
   */
  std::int32_t __cdecl mfCiGetFileSize(const char* const fileNameOrAddressRange)
  {
    std::uint32_t sizeBytes = 0;
    (void)mfci_get_adr_size(fileNameOrAddressRange, &sizeBytes);
    return static_cast<std::int32_t>(sizeBytes);
  }

  /**
   * Address: 0x00B137A0 (FUN_00B137A0, _mfci_alloc)
   *
   * What it does:
   * Returns the first free slot from the fixed MFCI handle pool.
   */
  std::int32_t __cdecl mfci_alloc()
  {
    for (MfciHandle& handle : mfci_obj) {
      if (handle.used == 0) {
        return MfciHandleToAddress(&handle);
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B137D0 (FUN_00B137D0, _mfci_free)
   *
   * What it does:
   * Clears one MFCI handle slot and returns zero.
   */
  std::int32_t __cdecl mfci_free(const std::int32_t handleAddress)
  {
    std::memset(AsMfciHandle(handleAddress), 0, sizeof(MfciHandle));
    return 0;
  }

  /**
   * Address: 0x00B137E0 (FUN_00B137E0, _mfci_reset_hn)
   *
   * What it does:
   * Reinitializes one MFCI handle slot after open/reset.
   */
  std::int32_t __cdecl mfci_reset_hn(const std::int32_t handleAddress)
  {
    MfciHandle* const handle = AsMfciHandle(handleAddress);

    handle->sectorSizeBytes = 0x800;
    handle->fileSizeBytes = mfCiGetFileSize(handle->addressAndSizeText);
    handle->used = 1;

    const std::int32_t sectorSizeBytes = handle->sectorSizeBytes;
    handle->sectorCount = (handle->fileSizeBytes + sectorSizeBytes - 1) / sectorSizeBytes;
    handle->sectorCursor = 0;
    handle->transferredSectors = 0;
    handle->transferredBytes = 0;
    handle->state = 0;
    return 0;
  }

  /**
   * Address: 0x00B138A0 (FUN_00B138A0, _mfCiClose)
   *
   * What it does:
   * Stops transfer state and releases one active MFCI handle slot.
   */
  void __cdecl mfCiClose(const std::int32_t handleAddress)
  {
    if (handleAddress == 0) {
      return;
    }

    mfCiStopTr(handleAddress);

    MfciHandle* const handle = AsMfciHandle(handleAddress);
    if (handle->used == 1) {
      handle->used = 0;
      (void)mfci_free(handleAddress);
    }
  }

  /**
   * Address: 0x00B138D0 (FUN_00B138D0, _mfCiSeek)
   *
   * What it does:
   * Updates one MFCI cursor lane by absolute/current/end origin and clamps it
   * to `[0, sectorCount]`.
   */
  std::int32_t __cdecl mfCiSeek(
    const std::int32_t handleAddress,
    const std::int32_t seekOffset,
    const std::int32_t seekOrigin
  )
  {
    if (handleAddress == 0) {
      (void)mfci_call_errfn(0, kMfciSeekNullHandleMessage);
      return 0;
    }

    MfciHandle* const handle = AsMfciHandle(handleAddress);

    mfCrsLock();
    switch (seekOrigin) {
    case 0:
      handle->sectorCursor = seekOffset;
      break;
    case 1:
      handle->sectorCursor += seekOffset;
      break;
    case 2:
      handle->sectorCursor = seekOffset + handle->sectorCount;
      break;
    default:
      break;
    }

    std::int32_t cursor = handle->sectorCursor;
    if (cursor >= handle->sectorCount) {
      cursor = handle->sectorCount;
    }
    handle->sectorCursor = (cursor <= 0) ? 0 : cursor;
    mfCrsUnlock();

    return handle->sectorCursor;
  }

  /**
   * Address: 0x00B13950 (FUN_00B13950, _mfCiTell)
   *
   * What it does:
   * Returns current MFCI cursor lane.
   */
  std::int32_t __cdecl mfCiTell(const std::int32_t handleAddress)
  {
    if (handleAddress != 0) {
      return AsMfciHandleConst(handleAddress)->sectorCursor;
    }

    (void)mfci_call_errfn(0, kMfciTellNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B13AC0 (FUN_00B13AC0, _mfCiStopTr)
   *
   * What it does:
   * Clears transfer-running state for one MFCI handle under MFCI lock.
   */
  void __cdecl mfCiStopTr(const std::int32_t handleAddress)
  {
    if (handleAddress == 0) {
      (void)mfci_call_errfn(0, kXeciNullHandleMessage);
      return;
    }

    mfCrsLock();
    AsMfciHandle(handleAddress)->state = 0;
    mfCrsUnlock();
  }

  /**
   * Address: 0x00B13AF0 (FUN_00B13AF0, _mfCiGetStat)
   *
   * What it does:
   * Returns signed transfer-state byte from one MFCI handle.
   */
  std::int32_t __cdecl mfCiGetStat(const std::int32_t handleAddress)
  {
    if (handleAddress != 0) {
      return static_cast<std::int32_t>(static_cast<std::int8_t>(AsMfciHandleConst(handleAddress)->state));
    }

    (void)mfci_call_errfn(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B13B10 (FUN_00B13B10, _mfCiGetSctLen)
   *
   * What it does:
   * Returns current MFCI sector-size lane from one media-file handle.
   */
  std::int32_t __cdecl mfCiGetSctLen(const std::int32_t handleAddress)
  {
    if (handleAddress != 0) {
      return AsMfciHandleConst(handleAddress)->sectorSizeBytes;
    }

    (void)mfci_call_errfn(0, kXeciGetSctLenNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B13B30 (FUN_00B13B30, _mfCiSetSctLen)
   *
   * What it does:
   * Updates MFCI sector geometry lanes and re-scales cursor/transfer state for
   * the requested sector size.
   */
  void __cdecl mfCiSetSctLen(const std::int32_t handleAddress, const std::int32_t sectorSizeBytes)
  {
    if (handleAddress == 0) {
      (void)mfci_call_errfn(0, kMfciSetSctLenNullHandleMessage);
      return;
    }

    MfciHandle* const handle = AsMfciHandle(handleAddress);
    const std::int32_t currentByteOffset = handle->sectorSizeBytes * handle->sectorCursor;

    handle->sectorSizeBytes = sectorSizeBytes;
    handle->sectorCount = (handle->fileSizeBytes + sectorSizeBytes - 1) / sectorSizeBytes;
    handle->transferredBytes = sectorSizeBytes * handle->transferredSectors;
    handle->sectorCursor = currentByteOffset / sectorSizeBytes;
  }

  /**
   * Address: 0x00B13B80 (FUN_00B13B80, _mfCiGetNumTr)
   *
   * What it does:
   * Returns transferred-byte count lane from one MFCI handle.
   */
  std::int32_t __cdecl mfCiGetNumTr(const std::int32_t handleAddress)
  {
    if (handleAddress != 0) {
      return AsMfciHandleConst(handleAddress)->transferredBytes;
    }

    (void)mfci_call_errfn(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B13BA0 (FUN_00B13BA0, _mfCiOpenEntry)
   *
   * What it does:
   * Allocates one MFCI handle for entry-based access and resets runtime lanes
   * when parameters are valid.
   */
  std::int32_t __cdecl mfCiOpenEntry(
    const std::int32_t entryCount,
    const std::int32_t /*openMode*/,
    const std::int32_t readWriteFlag
  )
  {
    if (entryCount <= 0) {
      (void)mfci_call_errfn(0, kMfciOpenEntryInvalidEntryCountMessage);
      return 0;
    }

    if (readWriteFlag != 0) {
      (void)mfci_call_errfn(0, kMfciOpenEntryInvalidRwModeMessage);
      return 0;
    }

    const std::int32_t handleAddress = mfci_alloc();
    if (handleAddress == 0) {
      (void)mfci_call_errfn(0, kMfciOpenEntryNoHandleResourceMessage);
      return 0;
    }

    (void)mfci_reset_hn(handleAddress);
    return handleAddress;
  }

  /**
   * Address: 0x00B13C10 (FUN_00B13C10, _mfCiOptFn1)
   *
   * What it does:
   * Dispatches legacy MFCI option IDs to transfer-count and parsed file-size
   * query lanes.
   */
  std::int32_t __cdecl mfCiOptFn1(const std::int32_t optionTargetAddress, const std::int32_t optionCode)
  {
    if (optionTargetAddress == 0) {
      return 0;
    }

    switch (optionCode) {
    case 200:
    case 202:
    case 204:
    case 299:
      return 0;
    case 201:
      return mfCiGetNumTr(optionTargetAddress);
    case 203:
    case 205:
      return mfCiGetFileSize(reinterpret_cast<const char*>(
        static_cast<std::uintptr_t>(static_cast<std::uint32_t>(optionTargetAddress))
      ));
    default:
      return 0;
    }
  }

  /**
   * Address: 0x00B11B60 (FUN_00B11B60, j__xeDirAppendRootDir)
   *
   * What it does:
   * Thunk alias that forwards to `xeDirAppendRootDir`.
   */
  char* __cdecl xeDirAppendRootDirThunk(char* const outputPath, const char* const relativeOrAbsolutePath)
  {
    return xeDirAppendRootDir(outputPath, relativeOrAbsolutePath);
  }

  /**
   * Address: 0x00B11BB0 (FUN_00B11BB0, _xeCiGetFileSizeLower)
   *
   * What it does:
   * Returns low 32-bit file-size lane for one XECI path.
   */
  std::int32_t __cdecl xeCiGetFileSizeLower(const char* const fileName)
  {
    return xeCiGetFileSize(fileName);
  }

  /**
   * Address: 0x00B110E0 (FUN_00B110E0, _xeCiGetFileSizeByHndl)
   *
   * What it does:
   * Returns the signed 64-bit file-size lane cached in one XECI object.
   */
  std::int64_t __cdecl xeCiGetFileSizeByHndl(const XeciObject* const object)
  {
    const std::uint64_t lowPart = static_cast<std::uint64_t>(object->fileSizeLow);
    const std::uint64_t highPart = static_cast<std::uint64_t>(static_cast<std::uint32_t>(object->fileSizeHigh)) << 32;
    return static_cast<std::int64_t>(highPart | lowPart);
  }

  /**
   * Address: 0x00B11120 (FUN_00B11120, xeci_obj_init)
   *
   * What it does:
   * Reinitializes one XECI object lane, rebuilds overlapped event state, and
   * computes transfer chunk count from current file-size lane.
   */
  HANDLE __cdecl xeci_obj_init(XeciObject* const object)
  {
    if (object->overlapped.hEvent != nullptr) {
      CloseHandle(object->overlapped.hEvent);
    }

    const std::int64_t roundedSize = xeCiGetFileSizeByHndl(object) + 0x7FF;
    object->readChunkSizeBytes = 0x800u;
    object->transferChunkCount = static_cast<std::uint32_t>(roundedSize / 0x800);
    object->currentChunkIndex = 0;
    object->readBufferPtr = nullptr;
    object->readChunkCount = 0;
    object->transferCountLow = 0;
    object->transferCountHigh = 0;
    object->state = 0;
    object->wantsRead = 0;
    object->wantsUpdate = 0;
    object->overlapped = {};
    object->overlapped.hEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    object->used = 1;
    return object->overlapped.hEvent;
  }

  /**
   * Address: 0x00B111A0 (FUN_00B111A0, xeci_obj_overlap_cleanup)
   *
   * What it does:
   * Closes one XECI object overlapped event lane then clears the full object.
   */
  std::int32_t __cdecl xeci_obj_overlap_cleanup(XeciObject* const object)
  {
    if (object->overlapped.hEvent != nullptr) {
      CloseHandle(object->overlapped.hEvent);
    }

    std::memset(object, 0, sizeof(XeciObject));
    return 0;
  }

  /**
   * Address: 0x00B11850 (FUN_00B11850, _xeCiGetNumTr)
   *
   * What it does:
   * Returns low transfer-count lane from one XECI object handle.
   */
  std::int32_t __cdecl xeCiGetNumTr(const XeciObject* const object)
  {
    if (object != nullptr) {
      return static_cast<std::int32_t>(object->transferCountLow);
    }

    xeci_assert(0, kXeciNullHandleMessage);
    return 0;
  }

  /**
   * Address: 0x00B11870 (FUN_00B11870, xeci_obj_cleanup)
   *
   * What it does:
   * Cleans up one XECI object lane, closing owned file handles and zeroing the
   * full object state under XECI lock.
   */
  void __cdecl xeci_obj_cleanup(XeciObject* const object)
  {
    if (object->fileHandleOwnedExternally == 0 && object->fileHandle != nullptr) {
      xeci_obj_handle_cleanup(object->fileHandle);
      object->fileHandle = nullptr;
    }

    xeci_lock();
    object->used = 0;
    xeci_obj_overlap_cleanup(object);
    xeci_unlock();
  }

  /**
   * Address: 0x00B118B0 (FUN_00B118B0, _xeci_create_func)
   *
   * What it does:
   * Opens one file handle for XECI object reads and restores caller lock depth.
   */
  HANDLE __cdecl xeci_create_func(LPCSTR fileName)
  {
    const std::int32_t removedLockCount = xeci_lock_count();
    const char* errorPath = fileName;

    HANDLE openedHandle = INVALID_HANDLE_VALUE;
    if (xeci_read_file_mode != 0) {
      wxCiLock();
      openedHandle = CreateFileA(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0x10000000u,
        nullptr
      );
      wxCiUnLock();
    } else {
      openedHandle = CreateFileA(
        fileName,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0x70000000u,
        nullptr
      );
    }

    if (openedHandle == INVALID_HANDLE_VALUE) {
      const DWORD lastError = GetLastError();
      std::sprintf(wxfic_cache_file, kXeciOpenFileFailedFormat, errorPath, lastError);
      xeci_assert(0, wxfic_cache_file);
      xeci_lock_n(removedLockCount);
      return nullptr;
    }

    xeci_lock_n(removedLockCount);
    return openedHandle;
  }

  /**
   * Address: 0x00B11960 (FUN_00B11960, xeci_obj_handle_cleanup)
   *
   * What it does:
   * Closes one handle through wxCi lock while preserving caller XECI lock depth.
   */
  void __cdecl xeci_obj_handle_cleanup(const HANDLE objectHandle)
  {
    const std::int32_t removedLockCount = xeci_lock_count();
    wxCiLock();
    CloseHandle(objectHandle);
    wxCiUnLock();
    xeci_lock_n(removedLockCount);
  }

  /**
   * Address: 0x00B11A40 (FUN_00B11A40, _xeUtyGetFileSizeEx)
   *
   * What it does:
   * Reads one file size lane under wxCi lock and returns the 64-bit byte count.
   */
  std::uint64_t __cdecl xeUtyGetFileSizeEx(const HANDLE fileHandle)
  {
    DWORD fileSizeHigh = 0;
    wxCiLock();
    const DWORD fileSizeLow = GetFileSize(fileHandle, &fileSizeHigh);
    wxCiUnLock();
    return (static_cast<std::uint64_t>(fileSizeHigh) << 32) | static_cast<std::uint64_t>(fileSizeLow);
  }

  /**
   * Address: 0x00B11B70 (FUN_00B11B70, _xeCiGetNumTrUpper)
   *
   * What it does:
   * Returns upper 32 bits from one XECI transfer-count lane.
   */
  std::uint64_t __cdecl xeCiGetNumTrUpper(const XeciObject* const object)
  {
    const std::uint64_t transferCount = (static_cast<std::uint64_t>(object->transferCountHigh) << 32)
      | static_cast<std::uint64_t>(object->transferCountLow);
    return transferCount >> 32;
  }

  /**
   * Address: 0x00B11B90 (FUN_00B11B90, _xeCiGetNumTrLower)
   *
   * What it does:
   * Returns lower 32 bits from one XECI transfer-count lane.
   */
  std::int32_t __cdecl xeCiGetNumTrLower(const XeciObject* const object)
  {
    return static_cast<std::int32_t>(object->transferCountLow);
  }

  /**
   * Address: 0x00B11BA0 (FUN_00B11BA0, _xeCiGetFileSizeUpper)
   *
   * What it does:
   * Returns constant zero for the legacy file-size-upper option lane.
   */
  std::int32_t __cdecl xeCiGetFileSizeUpper(const XeciObject* const /*object*/)
  {
    return 0;
  }

  /**
   * Address: 0x00B11A80 (FUN_00B11A80, sub_B11A80)
   *
   * What it does:
   * Updates the global XECI read-mode lane used by file-read dispatch.
   */
  void __cdecl xeci_set_read_mode(
    const std::int32_t /*unusedOptionA*/,
    const std::int32_t /*unusedOptionB*/,
    const std::int32_t /*unusedOptionC*/,
    const std::int32_t readMode
  )
  {
    xeci_read_file_mode = readMode;
  }

  /**
   * Address: 0x00B11BC0 (FUN_00B11BC0, sub_B11BC0)
   *
   * What it does:
   * Requests asynchronous read-abort handling for the active XECI transfer lane.
   */
  void __cdecl xeci_request_async_abort()
  {
    xeci_async_abort_requested = 1;
  }

  /**
   * Address: 0x00B11BD0 (FUN_00B11BD0, wxCiLock_init)
   *
   * What it does:
   * Initializes the wxCi file lock lane and routes read dispatch through chunked reads.
   */
  void wxCiLock_init()
  {
    if (InterlockedIncrement(&wxCiLock_inited) == 1) {
      xeci_set_read_mode(0, 0, 0, 1);
      InitializeCriticalSection(&wxCiLock_obj);
      wxCiLock_fn = &xeci_read_amt_from_file;
    }
  }

  /**
   * Address: 0x00B11C10 (FUN_00B11C10, wxCiLock_destroy)
   *
   * What it does:
   * Tears down the wxCi file lock lane once the final lock user releases it.
   */
  void wxCiLock_destroy()
  {
    if (InterlockedDecrement(&wxCiLock_inited) == 0) {
      wxCiLock_fn = nullptr;
      DeleteCriticalSection(&wxCiLock_obj);
    }
  }

  /**
   * Address: 0x00B11C30 (FUN_00B11C30, wxCiLock)
   *
   * What it does:
   * Enters the wxCi file critical section and increments nested lock depth.
   */
  std::int32_t wxCiLock()
  {
    const std::int32_t lockInitCount = static_cast<std::int32_t>(wxCiLock_inited);
    if (lockInitCount > 0) {
      EnterCriticalSection(&wxCiLock_obj);
      ++wxCiLock_count;
      return wxCiLock_count;
    }

    return lockInitCount;
  }

  /**
   * Address: 0x00B11C50 (FUN_00B11C50, wxCiUnLock)
   *
   * What it does:
   * Leaves the wxCi file critical section and reports unbalanced unlocks.
   */
  void wxCiUnLock()
  {
    if (wxCiLock_inited > 0) {
      --wxCiLock_count;
      if (wxCiLock_count >= 0) {
        LeaveCriticalSection(&wxCiLock_obj);
      } else {
        xeci_assert(0, kXeciUnlockBeforeLockMessage);
      }
    }
  }

  /**
   * Address: 0x00B11C90 (FUN_00B11C90, sub_B11C90)
   *
   * What it does:
   * Returns current nested wxCi lock depth.
   */
  std::int32_t wxCiLock_get_count()
  {
    return wxCiLock_count;
  }

  /**
   * Address: 0x00B11CA0 (FUN_00B11CA0, sub_B11CA0)
   *
   * What it does:
   * Returns current XECI chunk size used by chunked read dispatch.
   */
  DWORD xeci_get_chunk_size()
  {
    return xeci_chunk_size;
  }

  /**
   * Address: 0x00B11CB0 (FUN_00B11CB0, sub_B11CB0)
   *
   * What it does:
   * Updates XECI chunk size used by chunked read dispatch.
   */
  DWORD __cdecl xeci_set_chunk_size(const DWORD chunkSizeBytes)
  {
    xeci_chunk_size = chunkSizeBytes;
    return chunkSizeBytes;
  }

  /**
   * Address: 0x00B11CC0 (FUN_00B11CC0, xeci_read_file)
   *
   * What it does:
   * Dispatches one XECI file-read request through the current read callback lane.
   */
  BOOL __cdecl xeci_read_file(
    const HANDLE fileHandle,
    LPVOID buffer,
    const DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  )
  {
    if (wxCiLock_fn != nullptr) {
      return wxCiLock_fn(fileHandle, buffer, bytesToRead, outBytesRead, overlapped);
    }

    return ReadFile(fileHandle, buffer, bytesToRead, outBytesRead, overlapped);
  }

  /**
   * Address: 0x00B11CF0 (FUN_00B11CF0, xeci_read_amt_from_file)
   *
   * What it does:
   * Reads one file lane in fixed-size chunks under wxCi lock, then reads the tail.
   */
  BOOL __cdecl xeci_read_amt_from_file(
    const HANDLE fileHandle,
    LPVOID buffer,
    const DWORD bytesToRead,
    LPDWORD outBytesRead,
    LPOVERLAPPED overlapped
  )
  {
    DWORD bytesReadThisCall = 0;
    *outBytesRead = 0;

    std::int32_t fullChunkCount = static_cast<std::int32_t>(bytesToRead / xeci_chunk_size);
    const std::int32_t trailingBytes = static_cast<std::int32_t>(bytesToRead % xeci_chunk_size);
    std::int32_t chunkIndex = 0;
    if (fullChunkCount > 0) {
      while (true) {
        wxCiLock();
        const DWORD offsetBytes = static_cast<DWORD>(chunkIndex) * xeci_chunk_size;
        const BOOL readResult = ReadFile(
          fileHandle,
          static_cast<std::uint8_t*>(buffer) + offsetBytes,
          xeci_chunk_size,
          &bytesReadThisCall,
          overlapped
        );
        wxCiUnLock();

        *outBytesRead += bytesReadThisCall;
        if (readResult == FALSE) {
          return FALSE;
        }

        ++chunkIndex;
        if (chunkIndex >= fullChunkCount) {
          break;
        }
      }
    }

    if (trailingBytes > 0) {
      wxCiLock();
      const DWORD offsetBytes = static_cast<DWORD>(chunkIndex) * xeci_chunk_size;
      const BOOL readResult = ReadFile(
        fileHandle,
        static_cast<std::uint8_t*>(buffer) + offsetBytes,
        static_cast<DWORD>(trailingBytes),
        &bytesReadThisCall,
        overlapped
      );
      wxCiUnLock();

      *outBytesRead += bytesReadThisCall;
      if (readResult == FALSE) {
        return FALSE;
      }
    }

    return TRUE;
  }

  /**
   * Address: 0x00B1F250 (xeci_lock)
   *
   * What it does:
   * Enters the shared SVM lock lane used by XECI operations.
   */
  void __cdecl xeci_lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B1F260 (xeci_unlock)
   *
   * What it does:
   * Leaves the shared SVM lock lane used by XECI operations.
   */
  void __cdecl xeci_unlock()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B1F290 (xeci_is_locked)
   *
   * What it does:
   * Detects whether current thread runs at XECI lock priority.
   */
  BOOL xeci_is_locked()
  {
    return GetThreadPriority(GetCurrentThread()) == THREAD_PRIORITY_TIME_CRITICAL;
  }

  /**
   * Address: 0x00B1F2B0 (xeci_lock_count)
   *
   * What it does:
   * Force-unlocks nested XECI lock depth and returns removed count.
   */
  std::int32_t xeci_lock_count()
  {
    std::int32_t removedLocks = 0;
    while (xeci_is_locked() == TRUE) {
      xeci_unlock();
      ++removedLocks;
      xeci_error(0, kXeciForceUnlockedMessage);
    }
    return removedLocks;
  }

  /**
   * Address: 0x00B1F2E0 (xeci_lock_n)
   *
   * What it does:
   * Re-applies XECI lock nesting depth removed by `xeci_lock_count`.
   */
  void __cdecl xeci_lock_n(std::int32_t lockCount)
  {
    while (lockCount > 0) {
      xeci_lock();
      --lockCount;
    }
  }

  /**
   * Address: 0x00B10910 (FUN_00B10910, _xeCiInit)
   *
   * What it does:
   * Resets XECI root-path/object pools and forces synchronous read mode.
   */
  void xeCiInit()
  {
    std::memset(gXeDirRootDirectory.data(), 0, gXeDirRootDirectory.size());
    std::memset(xedir_work, 0, sizeof(xedir_work));
    xeci_set_read_mode(0, 0, 0, 1);
  }

  /**
   * Address: 0x00B10940 (FUN_00B10940, _xeCiFinish)
   *
   * What it does:
   * Drains XECI server work until every transfer object is released or timeout
   * is reached.
   */
  char* xeCiFinish()
  {
    std::int32_t spinCount = 0;
    char* firstUsedObject = reinterpret_cast<char*>(crierr_err_msg);

    for (; spinCount < kXeciTimeoutPollLimit; ++spinCount) {
      xeCiExecServer();

      std::int32_t clearedObjectCount = 0;
      firstUsedObject = reinterpret_cast<char*>(crierr_err_msg);
      for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
        XeciObject* const object = &xedir_work[objectIndex];
        if (object->used != 0) {
          firstUsedObject = reinterpret_cast<char*>(object);
          break;
        }
        ++clearedObjectCount;
      }

      if (clearedObjectCount == kXeciObjectCount) {
        break;
      }
    }

    if (spinCount == kXeciTimeoutPollLimit) {
      xeci_assert(0, kXeciCloseWaitTimeoutMessage);
    }
    return firstUsedObject;
  }

  /**
   * Address: 0x00B10A40 (xeci_wait_one_milli)
   *
   * What it does:
   * Waits about one millisecond while preserving XECI lock nesting.
   */
  void xeci_wait_one_milli()
  {
    std::int32_t forcedLockCount = xeci_lock_count();
    LARGE_INTEGER startCounter{};
    LARGE_INTEGER currentCounter{};
    LARGE_INTEGER frequency{};

    QueryPerformanceCounter(&startCounter);
    forcedLockCount += xeci_lock_count();
    QueryPerformanceCounter(&currentCounter);
    QueryPerformanceFrequency(&frequency);
    frequency.QuadPart /= kXeciWaitOneMilliDivisor;

    while ((currentCounter.QuadPart - startCounter.QuadPart) <= frequency.QuadPart) {
      if (currentCounter.QuadPart <= startCounter.QuadPart) {
        break;
      }

      forcedLockCount += xeci_lock_count();
      QueryPerformanceCounter(&currentCounter);
      QueryPerformanceFrequency(&frequency);
      frequency.QuadPart /= kXeciWaitOneMilliDivisor;
    }

    xeci_lock_n(forcedLockCount);
  }

  /**
   * Address: 0x00B10B90 (xeci_obj_update_overlapped)
   *
   * What it does:
   * Polls one overlapped read lane, updates transfer/error state, and reports
   * read failures through XECI error callback.
   */
  std::int32_t __cdecl xeci_obj_update_overlapped(XeciObject* const object)
  {
    if (xeci_read_file_mode != 0) {
      object->wantsUpdate = xeci_obj_currently_reading;
      return xeci_read_file_mode;
    }

    DWORD transferredBytes = 0;
    if (GetOverlappedResult(object->fileHandle, &object->overlapped, &transferredBytes, FALSE) != FALSE) {
      if (xeci_async_abort_requested == 1) {
        xeci_async_abort_requested = 0;
        object->wantsUpdate = 0;
        object->state = kXeciStateError;
        return TRUE;
      }

      object->wantsUpdate = 0;
      object->transferSizeBytes = transferredBytes;
      return static_cast<std::int32_t>(transferredBytes);
    }

    const DWORD lastError = GetLastError();
    if (lastError == ERROR_OPERATION_ABORTED) {
      xeci_assert(0, kXeciReadAbortedMessage);
      object->state = kXeciStateError;
    } else if (lastError == ERROR_HANDLE_EOF) {
      xeci_assert(0, kXeciReadReachedEofMessage);
      object->state = kXeciStateError;
    } else if (lastError != ERROR_IO_PENDING && lastError != ERROR_IO_INCOMPLETE) {
      std::sprintf(wxfic_cache_file, kXeciReadErrorFormat, lastError);
      xeci_assert(0, wxfic_cache_file);
      object->state = kXeciStateError;
    }

    if (object->state == kXeciStateError) {
      object->wantsUpdate = 0;
    }

    return object->state;
  }

  /**
   * Address: 0x00B10C70 (FUN_00B10C70, xeci_obj_update)
   *
   * What it does:
   * Services one XECI object transfer lane, finalizing completed reads into the
   * buffered chunk state.
   */
  void __cdecl xeci_obj_update(XeciObject* const object)
  {
    std::int32_t* const updateLockFlag = &object->updateLockFlag;
    if (SofdecSetTrueThunk(updateLockFlag) == TRUE) {
      if (object->state == kXeciStateTransferring) {
        if (object->wantsRead == 1) {
          (void)xeci_obj_read_from_file(object);
        }

        if (object->wantsUpdate == 1) {
          (void)xeci_obj_update_overlapped(object);
          if (object->wantsUpdate == 0 && object->state != kXeciStateError) {
            xeci_lock();

            const std::uint32_t chunkSizeBytes = object->readChunkSizeBytes;
            const std::uint32_t transferredBytes = object->transferSizeBytes;
            const std::uint32_t remainderBytes = transferredBytes % chunkSizeBytes;
            if (remainderBytes != 0u) {
              auto* const readBufferBase = static_cast<std::uint8_t*>(object->readBufferPtr);
              std::memset(readBufferBase + transferredBytes, 0, chunkSizeBytes - remainderBytes);
            }

            const std::int32_t chunkAdvance = object->readChunkCount;
            const std::int64_t transferBytes
              = static_cast<std::int64_t>(chunkAdvance) * static_cast<std::int64_t>(object->readChunkSizeBytes);
            object->transferCountLow = static_cast<std::uint32_t>(transferBytes);
            object->transferCountHigh = static_cast<std::uint32_t>(static_cast<std::uint64_t>(transferBytes) >> 32);
            object->currentChunkIndex += chunkAdvance;
            object->state = 1;
            xeci_unlock();
          }
        }
      }
      *updateLockFlag = 0;
    }
  }

  /**
   * Address: 0x00B10D20 (FUN_00B10D20, xeci_obj_read_from_file)
   *
   * What it does:
   * Starts one synchronous/asynchronous file read for the current XECI object
   * lane and maps Win32 read failures to XECI error codes.
   */
  BOOL __cdecl xeci_obj_read_from_file(XeciObject* const object)
  {
    DWORD numberOfBytesRead = 0;
    BOOL readResult = FALSE;

    xeci_lock();
    object->wantsRead = 0;
    object->wantsUpdate = 1;
    xeci_obj_currently_reading = 1;
    xeci_unlock();

    if (xeci_read_file_mode != 0) {
      LONG distanceToMoveHigh = object->readOffsetHigh;
      const LONG distanceToMove = object->readOffsetLow;
      wxCiLock();
      SetFilePointer(object->fileHandle, distanceToMove, &distanceToMoveHigh, FILE_BEGIN);
      wxCiUnLock();

      readResult = xeci_read_file(object->fileHandle, object->readBufferPtr, object->transferSizeBytes, &numberOfBytesRead, nullptr);
      if (readResult != FALSE && numberOfBytesRead == 0u) {
        xeci_assert(0, kXeciReadZeroByteSyncMessage);
        object->state = kXeciStateError;
      }

      object->transferSizeBytes = numberOfBytesRead;
    } else {
      object->overlapped.Offset = static_cast<DWORD>(object->readOffsetLow);
      object->overlapped.OffsetHigh = static_cast<DWORD>(object->readOffsetHigh);
      readResult = ReadFile(
        object->fileHandle,
        object->readBufferPtr,
        object->transferSizeBytes,
        nullptr,
        &object->overlapped
      );
    }

    xeci_obj_currently_reading = 0;
    if (readResult == FALSE) {
      xeci_lock();
      const DWORD lastError = GetLastError();

      if (lastError > ERROR_HANDLE_EOF) {
        if (lastError != ERROR_IO_PENDING) {
          if (lastError == ERROR_INVALID_USER_BUFFER) {
            xeci_assert(0, kXeciReadQueueOverflowMessage);
            object->state = kXeciStateError;
          } else {
            std::sprintf(wxfic_cache_file, kXeciReadLastErrorFormat, lastError);
            xeci_assert(0, wxfic_cache_file);
            object->state = kXeciStateError;
          }
        }
      } else if (lastError == ERROR_HANDLE_EOF) {
        xeci_assert(0, kXeciReadInvalidStartMessage);
        object->state = kXeciStateError;
      } else if (lastError == ERROR_INVALID_HANDLE) {
        xeci_assert(0, kXeciReadInvalidHandleMessage);
        object->state = kXeciStateError;
      } else if (lastError == ERROR_NOT_ENOUGH_MEMORY) {
        xeci_assert(0, kXeciReadQueueOverflowMessage);
        object->state = kXeciStateError;
      } else if (lastError == ERROR_READ_FAULT) {
        xeci_assert(0, kXeciReadFaultMessage);
        object->state = kXeciStateError;
      } else {
        std::sprintf(wxfic_cache_file, kXeciReadLastErrorFormat, lastError);
        xeci_assert(0, wxfic_cache_file);
        object->state = kXeciStateError;
      }

      if (object->state == kXeciStateError) {
        object->wantsUpdate = 0;
      }
      xeci_unlock();
    }

    return readResult;
  }

  /**
   * Address: 0x00B10EA0 (FUN_00B10EA0, sub_B10EA0)
   *
   * What it does:
   * Returns whether any XECI object is still in active transfer state.
   */
  std::int32_t __cdecl xeci_has_active_transfer()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      const XeciObject& object = xedir_work[objectIndex];
      if (object.used != 0 && object.state == kXeciStateTransferring) {
        return 1;
      }
    }
    return 0;
  }

  /**
   * Address: 0x00B10ED0 (FUN_00B10ED0, _xeCiExecServer)
   *
   * What it does:
   * Updates every used XECI object, then fires idle callback when no active
   * transfer remains.
   */
  void __cdecl xeCiExecServer()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      XeciObject& object = xedir_work[objectIndex];
      if (object.used == 1) {
        xeci_obj_update(&object);
      }
    }

    if (xeci_has_active_transfer() != 1) {
      if (xeci_server_idle_callback != nullptr) {
        xeci_server_idle_callback(0);
      }
    }
  }

  /**
   * Address: 0x00B116D0 (xeci_obj_wait_until_done)
   *
   * What it does:
   * Waits until one XECI object completes pending transfer/update state.
   */
  void __cdecl xeci_obj_wait_until_done(XeciObject* const object)
  {
    std::int32_t pollCount = 0;
    while (object->wantsUpdate != 0) {
      xeci_obj_update_overlapped(object);
      xeci_wait_one_milli();

      ++pollCount;
      if (pollCount >= kXeciTimeoutPollLimit) {
        xeci_assert(0, kXeciWaitTimeoutMessage);
        xeci_lock();
        object->state = kXeciStateError;
        object->wantsUpdate = 0;
        xeci_unlock();
        return;
      }
    }
  }

  /**
   * Address: 0x00B11660 (_xeCiStopTr)
   *
   * What it does:
   * Stops one active transfer lane and clears pending read request state.
   */
  void __cdecl xeCiStopTr(XeciObject* const object)
  {
    if (object == nullptr) {
      xeci_assert(0, kXeciNullHandleMessage);
      return;
    }

    if (object->state == 0) {
      return;
    }

    if (object->state == kXeciStateTransferring) {
      xeci_obj_wait_until_done(object);
      object->state = 0;
    }

    object->wantsRead = 0;
  }

  /**
   * Address: 0x00B116A0 (xeci_wait_until_all_done)
   *
   * What it does:
   * Waits for completion on every used XECI transfer object in the global pool.
   */
  void xeci_wait_until_all_done()
  {
    for (std::int32_t objectIndex = 0; objectIndex < kXeciObjectCount; ++objectIndex) {
      XeciObject& object = xedir_work[objectIndex];
      if (object.used != 0) {
        xeci_obj_wait_until_done(&object);
      }
    }
  }

  /**
   * Address: 0x00B205C0 (xeci_create_thread)
   *
   * What it does:
   * Starts suspended XECI worker thread, applies priority settings, then
   * resumes it.
   */
  void xeci_create_thread()
  {
    xeci_thread = CreateThread(nullptr, 0x3000u, xeci_thread_server, nullptr, CREATE_SUSPENDED, nullptr);
    if (xeci_thread == nullptr) {
      xeci_error(0, kCreateThreadFailedMessage);
      return;
    }

    SetThreadPriority(xeci_thread, 1);
    SetThreadPriorityBoost(xeci_thread, TRUE);
    if (ResumeThread(xeci_thread) == 0xFFFFFFFFu) {
      xeci_error(0, kResumeThreadFailedMessage);
    }
  }

  /**
   * Address: 0x00B20630 (xeci_destroy_thread)
   *
   * What it does:
   * Signals worker shutdown, waits for thread exit, closes handle, and clears
   * global thread handle lane.
   */
  BOOL xeci_destroy_thread()
  {
    xeci_is_done = 1;
    WaitForSingleObject(xeci_thread, INFINITE);
    const BOOL closeResult = CloseHandle(xeci_thread);
    xeci_thread = nullptr;
    return closeResult;
  }

  /**
   * Address: 0x00B20660 (xeci_thread_server)
   *
   * What it does:
   * Polls active XEFIC objects for queued work, processes work items, runs
   * completion callback lane, and advances object state lanes.
   */
  DWORD __stdcall xeci_thread_server(LPVOID /*threadParameter*/)
  {
    while (xeci_is_done == 0) {
      for (auto* object = xefic_crs; object < xefic_crs + kXeficObjectCount; ++object) {
        if (object->used != 0 && object->hasWork == 1) {
          xefic_RebuildObjectQueue(object);
          object->queueCursor = object->queueHead;

          if (xefic_work_complete_callback != nullptr) {
            xefic_work_complete_callback(object);
          }

          if (object->state != 6) {
            object->state = 2;
          }

          object->hasWork = 0;
          Sleep(kXeficWorkerSleepMilliseconds);
        }
      }
      Sleep(kXeficWorkerSleepMilliseconds);
    }

    return 0;
  }

  /**
   * Address: 0x00B206E0 (xeci_save_thread_prio)
   *
   * What it does:
   * Saves current thread priority and elevates current thread to priority `2`.
   */
  BOOL xeci_save_thread_prio()
  {
    HANDLE currentThread = GetCurrentThread();
    xeci_old_thread_prio = GetThreadPriority(currentThread);
    return SetThreadPriority(currentThread, 2);
  }

  /**
   * Address: 0x00B20700 (xeci_set_thread_prio)
   *
   * What it does:
   * Restores current thread priority from saved XECI priority lane.
   */
  BOOL xeci_set_thread_prio()
  {
    return SetThreadPriority(GetCurrentThread(), xeci_old_thread_prio);
  }

  /**
   * Address: 0x00B20720 (_CRIERR_SetCbErr)
   *
   * What it does:
   * Sets or clears CRIERR callback function/object lanes and clears last error
   * message buffer.
   */
  std::int32_t CRIERR_SetCbErr(moho::AdxmErrorCallback callbackFunction, const std::int32_t callbackObject)
  {
    if (callbackFunction != nullptr) {
      crierr_callback_func = callbackFunction;
      crierr_callback_obj = callbackObject;
    } else {
      crierr_callback_func = nullptr;
      crierr_callback_obj = 0;
    }

    std::memset(crierr_err_msg, 0, sizeof(crierr_err_msg));
    return 0;
  }

  /**
   * Address: 0x00B10730 (FUN_00B10730, _ADXERR_Init)
   *
   * What it does:
   * Clears ADXERR message/callback lanes and returns success.
   */
  std::int32_t ADXERR_Init()
  {
    std::memset(crierr_err_msg, 0, sizeof(crierr_err_msg));
    crierr_callback_func = nullptr;
    crierr_callback_obj = 0;
    return 0;
  }

  /**
   * Address: 0x00B10750 (FUN_00B10750, _ADXERR_Finish)
   *
   * What it does:
   * Finalizes ADXERR by clearing message/callback lanes and returning success.
   */
  std::int32_t ADXERR_Finish()
  {
    std::memset(crierr_err_msg, 0, sizeof(crierr_err_msg));
    crierr_callback_func = nullptr;
    crierr_callback_obj = 0;
    return 0;
  }

  /**
   * Address: 0x00B10770 (FUN_00B10770, _ADXERR_EntryErrFunc)
   *
   * What it does:
   * Registers ADXERR callback/object lanes and forwards the same pair to SVM.
   */
  void ADXERR_EntryErrFunc(const moho::AdxmErrorCallback callbackFunction, const std::int32_t callbackObject)
  {
    crierr_callback_func = callbackFunction;
    crierr_callback_obj = callbackObject;
    SVM_SetCbErr(callbackFunction, callbackObject);
  }

  /**
   * Address: 0x00B15D90 (FUN_00B15D90, j__CRIERR_SetCbErr)
   *
   * What it does:
   * Thunk wrapper to `CRIERR_SetCbErr`.
   */
  std::int32_t j__CRIERR_SetCbErr(
    const moho::AdxmErrorCallback callbackFunction,
    const std::int32_t callbackObject
  )
  {
    return CRIERR_SetCbErr(callbackFunction, callbackObject);
  }

  /**
   * Address: 0x00B10790 (FUN_00B10790, _ADXERR_CallErrFunc1_)
   *
   * What it does:
   * Copies one ADX error message lane, dispatches registered callback, then
   * forwards the same text through `SVM_CallErr`.
   */
  int ADXERR_CallErrFunc1_(const char* const message)
  {
    std::strncpy(crierr_err_msg, message, kAdxerrCopyLimit);
    if (crierr_callback_func != nullptr) {
      crierr_callback_func(static_cast<std::uint32_t>(crierr_callback_obj), crierr_err_msg);
    }
    SVM_CallErr(crierr_err_msg);
    return 0;
  }

  /**
   * Address: 0x00B107D0 (FUN_00B107D0, _ADXERR_CallErrFunc2_)
   *
   * What it does:
   * Builds one combined ADX error string from prefix + detail text, dispatches
   * callback, and forwards through `SVM_CallErr`.
   */
  int ADXERR_CallErrFunc2_(const char* const prefix, const char* const message)
  {
    std::strncpy(crierr_err_msg, prefix, kAdxerrCopyLimit);
    std::strncat(crierr_err_msg, message, kAdxerrCopyLimit);
    if (crierr_callback_func != nullptr) {
      crierr_callback_func(static_cast<std::uint32_t>(crierr_callback_obj), crierr_err_msg);
    }
    SVM_CallErr(crierr_err_msg);
    return 0;
  }

  /**
   * Address: 0x00B10830 (FUN_00B10830, _ADXERR_ItoA)
   *
   * What it does:
   * Converts one integer lane to decimal text inside caller-provided buffer.
   */
  std::int32_t ADXERR_ItoA(const std::int32_t value, char* const outText, const std::int32_t outBytes)
  {
    if (outText == nullptr || outBytes <= 0) {
      return 0;
    }

    std::snprintf(outText, static_cast<std::size_t>(outBytes), "%d", value);
    return static_cast<std::int32_t>(std::strlen(outText));
  }

  /**
   * Address: 0x00B10890 (FUN_00B10890, _ADXERR_ItoA2)
   *
   * What it does:
   * Formats two integer lanes into one compact ADX error-text payload.
   */
  void ADXERR_ItoA2(
    const std::int32_t highWord,
    const std::int32_t lowWord,
    char* const outText,
    const std::int32_t outBytes
  )
  {
    (void)ADXERR_ItoA(highWord, outText, outBytes);
    std::strncat(outText, kAdxerrSeparator, outBytes - (static_cast<std::int32_t>(std::strlen(outText)) + 1));
    const std::int32_t usedBytes = static_cast<std::int32_t>(std::strlen(outText));
    const std::int32_t lowWordBytes = 4 - usedBytes;
    if (lowWordBytes > 0) {
      (void)ADXERR_ItoA(lowWord, outText + usedBytes, lowWordBytes);
    }
  }

  /**
   * Address: 0x00B207B0 (_crierr_default_callback)
   *
   * What it does:
   * Default CRIERR callback stub (no-op).
   */
  void crierr_default_callback()
  {
  }

  /**
   * Address: 0x00B207C0 (nullsub_41)
   *
   * What it does:
   * ADX RNA finalize hook stub (no-op).
   */
  void adxrna_NoOpFinalizeHook()
  {
  }

  /**
   * Address: 0x00B207D0 (_CRICRS_Enter)
   *
   * What it does:
   * Enters Sofdec RNA global critical section.
   */
  void CRICRS_Enter()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B207E0 (_CRICRS_Leave)
   *
   * What it does:
   * Leaves Sofdec RNA global critical section.
   */
  void CRICRS_Leave()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B15840 (FUN_00B15840, sub_B15840)
   *
   * What it does:
   * Returns ADXRNA transfer-enable bit (`stateFlags bit0`) for one RNA handle.
   */
  [[maybe_unused]] std::int32_t adxrna_IsTransferEnabled(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return static_cast<std::int32_t>(AsAdxrnaTransportRuntimeView(rnaHandle)->stateFlags & 0x01u);
  }

  /**
   * Address: 0x00B14BA0 (FUN_00B14BA0, _ADXRNA_Stop)
   *
   * What it does:
   * Forwards one stop request to ADXRNA output runtime dispatch slot `0x58`.
   */
  void ADXRNA_Stop(const std::int32_t rnaHandle)
  {
    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    (void)runtime->outputRuntime->dispatchTable->stopPlayback(runtime->outputRuntime, 0);
  }

  /**
   * Address: 0x00B14C30 (FUN_00B14C30, sub_B14C30)
   *
   * What it does:
   * Polls ADXRNA output lanes for stop completion and clears stop-pending lane.
   */
  [[maybe_unused]] std::int32_t adxrna_PollTransferStopState(const std::int32_t rnaHandle)
  {
    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    if (runtime->transferStopPending == 0) {
      return 0;
    }

    std::int32_t channel0Stopped = 1;
    std::int32_t channel1Stopped = 1;
    const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      if (runtime->outputRuntime->dispatchTable->isChannelStopped(runtime->outputRuntime, channelIndex) != 1) {
        if (channelIndex == 0) {
          channel0Stopped = 0;
        } else {
          channel1Stopped = 0;
        }
      }
    }

    if (channel0Stopped == 0 || channel1Stopped == 0) {
      return 0;
    }

    runtime->transferStopPending = 0;
    return 1;
  }

  /**
   * Address: 0x00B14BF0 (FUN_00B14BF0, sub_B14BF0)
   *
   * What it does:
   * Repeatedly polls ADXRNA stop completion up to 200 iterations.
   */
  [[maybe_unused]] std::int32_t adxrna_WaitForTransferStop(const std::int32_t rnaHandle)
  {
    gAdxrnaTransferDrainPollCount = 0;
    std::int32_t pollResult = 0;
    for (std::int32_t pollIndex = 0; pollIndex < kAdxrnaTransferDrainPollLimit; ++pollIndex) {
      pollResult = adxrna_PollTransferStopState(rnaHandle);
      if (pollResult == 1) {
        break;
      }

      ++gAdxrnaTransferDrainPollCount;
    }

    return pollResult;
  }

  /**
   * Address: 0x00B14E10 (FUN_00B14E10, sub_B14E10)
   *
   * What it does:
   * Advances ADXRNA transfer cursors by pending carry units and returns the new
   * accumulated transfer-unit lane.
   */
  [[maybe_unused]] std::int32_t adxrna_AdvanceTransferCursors(const std::int32_t rnaHandle)
  {
    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    const std::int32_t transferCarryUnits = runtime->transferCarryUnits;
    const std::int32_t combinedWritePosition = transferCarryUnits + runtime->transferFreezePosition;
    runtime->transferCarryUnits = 0;
    runtime->transferFreezePosition = combinedWritePosition % runtime->transferRingSize;

    const std::int32_t accumulatedUnits = transferCarryUnits + runtime->transferAccumulatedUnits;
    runtime->transferAccumulatedUnits = accumulatedUnits;
    return accumulatedUnits;
  }

  /**
   * Address: 0x00B14D90 (FUN_00B14D90, mwlRnaAddWrPos)
   *
   * What it does:
   * Applies pending transfer units to ADXRNA write/queue/time cursors.
   */
  [[maybe_unused]] void __cdecl mwlRnaAddWrPos(AdxrnaTransportRuntimeView* const runtime)
  {
    CRICRS_Enter();

    const std::int32_t channelCount = static_cast<std::int32_t>(runtime->channelCount);
    for (std::int32_t channelIndex = 0; channelIndex < channelCount; ++channelIndex) {
      void* const sjHandle = (channelIndex == 0) ? runtime->channelJoinHandle0 : runtime->channelJoinHandle1;
      if (sjHandle == nullptr) {
        CRIERR_CallErr(kMwlRnaAddWrPosNullSjMessage);
      }
    }

    const std::int32_t pendingUnits = runtime->pendingTransferUnits;
    const std::int32_t wrappedWritePosition = (runtime->transferWritePosition + pendingUnits) % runtime->transferRingSize;
    const std::int32_t queuedUnits = runtime->queuedDataUnits + pendingUnits;

    runtime->pendingTransferUnits = 0;
    runtime->queuedDataUnits = queuedUnits;
    runtime->transferWritePosition = wrappedWritePosition;
    runtime->decodedDataUnits += pendingUnits;

    CRICRS_Leave();
  }

  /**
   * Address: 0x00B14CB0 (FUN_00B14CB0, _ADXRNA_SetTransSw)
   *
   * What it does:
   * Updates ADXRNA transfer-enable lane and synchronizes transfer cursors.
   */
  void ADXRNA_SetTransSw(const std::int32_t rnaHandle, const std::int32_t enabled)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    const std::uint8_t pendingTransferAck = runtime->pendingTransferAck;
    runtime->transitionGuardFlag = 1;
    if (pendingTransferAck == 1u) {
      (void)adxrna_WaitForTransferStop(rnaHandle);
      if (adxrna_IsTransferEnabled(rnaHandle) == 1) {
        mwlRnaAddWrPos(runtime);
      } else {
        (void)adxrna_AdvanceTransferCursors(rnaHandle);
      }
      runtime->pendingTransferAck = 0;
    }

    CRICRS_Enter();
    runtime->transitionGuardFlag = 0;
    if (enabled != 0) {
      if (enabled == 1 && adxrna_IsTransferEnabled(rnaHandle) != 1) {
        const std::uint8_t stateFlags = runtime->stateFlags;
        runtime->transferWritePosition = 0;
        runtime->transferReadPosition = 0;
        runtime->queuedDataUnits = 0;
        runtime->decodeControlFlags = 0;
        runtime->transferStopPending = 0;
        runtime->decodeCursorUnits = 0;
        runtime->decodedDataUnits = 0;
        runtime->pendingTransferUnits = 0;
        runtime->transportResetState = 0;
        runtime->transferFreezePosition = 0;
        runtime->transferAccumulatedUnits = 0;
        runtime->stateFlags = static_cast<std::uint8_t>(stateFlags | 0x01u);
      }
    } else if (adxrna_IsTransferEnabled(rnaHandle) != 0) {
      const std::uint8_t stateFlags = runtime->stateFlags;
      runtime->transferFreezePosition = runtime->transferWritePosition;
      runtime->transferCarryUnits = 0;
      runtime->transferAccumulatedUnits = 0;
      runtime->stateFlags = static_cast<std::uint8_t>(stateFlags & 0x06u);
    }

    CRICRS_Leave();
  }

  /**
   * Address: 0x00B14A40 (FUN_00B14A40, sub_B14A40)
   *
   * What it does:
   * Drains and tears down one ADXRNA runtime object, including output runtime
   * destruction and full object reset.
   */
  [[maybe_unused]] std::int32_t adxrna_DestroyCore(AdxrnaTransportRuntimeView* const runtime)
  {
    if (runtime == nullptr) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    CRICRS_Enter();
    if (runtime->stateFlags != 0) {
      ADXRNA_Stop(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(runtime)));
      while (runtime->serverPendingCount != 0) {
        ADXRNA_ExecServer();
        ADXRNA_Stop(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(runtime)));
      }
    }
    CRICRS_Leave();

    CRICRS_Enter();
    while (gAdxrnaDestroyGuard != 0) {
      CRICRS_Leave();
      (void)adxrna_WaitForTransferStop(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(runtime)));
      CRICRS_Enter();
    }
    gAdxrnaDestroyGuard = 1;
    CRICRS_Leave();

    runtime->inUse = 0;
    const std::int32_t maxChannelCount = static_cast<std::int32_t>(runtime->maxChannelCount);
    for (std::int32_t channelIndex = 0; channelIndex < maxChannelCount; ++channelIndex) {
      if (channelIndex == 0) {
        runtime->channelJoinHandle0 = nullptr;
      } else {
        runtime->channelJoinHandle1 = nullptr;
      }
    }

    runtime->outputRuntime->dispatchTable->destroyOutput(runtime->outputRuntime);
    std::memset(runtime, 0, sizeof(AdxrnaTransportRuntimeView));
    gAdxrnaDestroyGuard = 0;
    return 0;
  }

  /**
   * Address: 0x00B14B40 (FUN_00B14B40, sub_B14B40)
   *
   * What it does:
   * Transitions ADXRNA into stop/replay transfer state and enables transfer.
   */
  [[maybe_unused]] void adxrna_StopAndEnableTransfer(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    CRICRS_Enter();
    if (runtime->stateFlags != 0) {
      ADXRNA_Stop(rnaHandle);
    }

    runtime->stateFlags = 4;
    runtime->restoreWritePosition = runtime->restoreReadPosition;
    ADXRNA_SetTransSw(rnaHandle, 1);
    CRICRS_Leave();
  }

  /**
   * Address: 0x00B17BF0 (FUN_00B17BF0, _ADXRNA_EntryErrFunc)
   *
   * What it does:
   * Thunk wrapper to CRIERR callback registration for ADXRNA lane.
   */
  std::int32_t ADXRNA_EntryErrFunc(
    const moho::AdxmErrorCallback callbackFunction,
    const std::int32_t callbackObject
  )
  {
    return j__CRIERR_SetCbErr(callbackFunction, callbackObject);
  }

  /**
   * Address: 0x00B17C00 (FUN_00B17C00, _ADXRNA_Create)
   *
   * What it does:
   * Thunk wrapper to RNA runtime creation.
   */
  std::int32_t ADXRNA_Create(const std::int32_t sourceJoinHandleTableAddress, const std::int32_t channelCount)
  {
    return static_cast<std::int32_t>(
      reinterpret_cast<std::uintptr_t>(mwRnaCreate(sourceJoinHandleTableAddress, channelCount))
    );
  }

  /**
   * Address: 0x00B17C10 (FUN_00B17C10, _ADXRNA_Destroy)
   *
   * What it does:
   * Stops one ADXRNA runtime and forwards teardown to destroy core.
   */
  void ADXRNA_Destroy(const std::int32_t rnaHandle)
  {
    ADXRNA_Stop(rnaHandle);
    (void)adxrna_DestroyCore(AsAdxrnaTransportRuntimeView(rnaHandle));
  }

  /**
   * Address: 0x00B17C30 (FUN_00B17C30, sub_B17C30)
   *
   * What it does:
   * Thunk wrapper to ADXRNA stop/replay transfer transition.
   */
  [[maybe_unused]] void ADXRNA_StopAndEnableTransferThunk(const std::int32_t rnaHandle)
  {
    adxrna_StopAndEnableTransfer(rnaHandle);
  }

  /**
   * Address: 0x00B17C40 (FUN_00B17C40, j__ADXRNA_Stop)
   *
   * What it does:
   * Thunk wrapper to `ADXRNA_Stop`.
   */
  void j__ADXRNA_Stop(const std::int32_t rnaHandle)
  {
    ADXRNA_Stop(rnaHandle);
  }

  /**
   * Address: 0x00B17C50 (FUN_00B17C50, j__ADXRNA_SetTransSw)
   *
   * What it does:
   * Thunk wrapper to `ADXRNA_SetTransSw`.
   */
  void j__ADXRNA_SetTransSw(const std::int32_t rnaHandle, const std::int32_t enabled)
  {
    ADXRNA_SetTransSw(rnaHandle, enabled);
  }

  /**
   * Address: 0x00B157C0 (FUN_00B157C0, sub_B157C0)
   *
   * What it does:
   * Returns constant discard-sample status `0` for this ADXRNA build.
   */
  [[maybe_unused]] std::int32_t adxrna_DiscardSamplesCoreNoOp()
  {
    return 0;
  }

  /**
   * Address: 0x00B157D0 (FUN_00B157D0, sub_B157D0)
   *
   * What it does:
   * Returns ADXRNA time-scale base lane and emits queued/decoded delta units.
   */
  [[maybe_unused]] std::int32_t adxrna_GetTimeCore(
    const std::int32_t rnaHandle,
    std::int32_t* const outQueuedDeltaUnits,
    std::int32_t* const outTimeScaleBase
  )
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return 0;
    }

    const auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    *outQueuedDeltaUnits = runtime->decodedDataUnits - runtime->queuedDataUnits;
    const std::int32_t timeScaleBase = AsAdxrnaLegacyMetricsRuntimeView(rnaHandle)->timeScaleBase;
    *outTimeScaleBase = timeScaleBase;
    return timeScaleBase;
  }

  /**
   * Address: 0x00B17C70 (FUN_00B17C70, _ADXRNA_GetTime)
   *
   * What it does:
   * Thunk wrapper to ADXRNA time query core.
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetTime(
    const std::int32_t rnaHandle,
    std::int32_t* const outQueuedDeltaUnits,
    std::int32_t* const outTimeScaleBase
  )
  {
    return adxrna_GetTimeCore(rnaHandle, outQueuedDeltaUnits, outTimeScaleBase);
  }

  /**
   * Address: 0x00B158C0 (FUN_00B158C0, sub_B158C0)
   *
   * What it does:
   * Returns ADXRNA queued-data lane at offset `0x34`.
   */
  [[maybe_unused]] std::int32_t adxrna_GetNumDataCore(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return AsAdxrnaTransportRuntimeView(rnaHandle)->queuedDataUnits;
  }

  /**
   * Address: 0x00B17C80 (FUN_00B17C80, _ADXRNA_GetNumData)
   *
   * What it does:
   * Thunk wrapper to ADXRNA queued-data query core.
   */
  std::int32_t ADXRNA_GetNumData(const std::int32_t rnaHandle)
  {
    return adxrna_GetNumDataCore(rnaHandle);
  }

  /**
   * Address: 0x00B15860 (FUN_00B15860, sub_B15860)
   *
   * What it does:
   * Returns ADXRNA play-flag bit (`stateFlags bit1`) for one RNA handle.
   */
  std::int32_t ADXRNA_IsPlaySwEnabled(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    const auto* const runtime = AsAdxrnaPlaySwitchRuntimeView(rnaHandle);
    return static_cast<std::int32_t>((runtime->stateFlags >> 1) & 1u);
  }

  /**
   * Address: 0x00B15890 (FUN_00B15890, sub_B15890)
   *
   * What it does:
   * Returns ADXRNA transfer-state bit2 from transport `stateFlags`.
   */
  [[maybe_unused]] std::int32_t ADXRNA_IsTransportFlagBit2Set(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    return static_cast<std::int32_t>((AsAdxrnaTransportRuntimeView(rnaHandle)->stateFlags >> 2) & 1u);
  }

  /**
   * Address: 0x00B158E0 (FUN_00B158E0, sub_B158E0)
   *
   * What it does:
   * Returns ADXRNA transfer headroom (`ringSize - queuedUnits`).
   */
  [[maybe_unused]] std::int32_t ADXRNA_GetTransferHeadroomUnits(const std::int32_t rnaHandle)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return -1;
    }

    const auto* const runtime = AsAdxrnaTransportRuntimeView(rnaHandle);
    return runtime->transferRingSize - runtime->queuedDataUnits;
  }

  /**
   * Address: 0x00B14E40 (FUN_00B14E40, _ADXRNA_SetPlaySw)
   *
   * What it does:
   * Updates ADXRNA play-switch lane and transition flags under RNA lock.
   */
  void ADXRNA_SetPlaySw(const std::int32_t rnaHandle, const std::int32_t enabled)
  {
    if (rnaHandle == 0) {
      CRIERR_CallErr(kAdxrnaIllegalParameterMessage);
      return;
    }

    auto* const runtime = AsAdxrnaPlaySwitchRuntimeView(rnaHandle);
    CRICRS_Enter();
    runtime->playSwitch = enabled;

    if (enabled != 0) {
      if (enabled == 1 && ADXRNA_IsPlaySwEnabled(rnaHandle) != 1) {
        runtime->stateFlags = static_cast<std::uint8_t>(runtime->stateFlags | 0x02u);
      }
    } else if (ADXRNA_IsPlaySwEnabled(rnaHandle) != 0) {
      runtime->stateFlags = static_cast<std::uint8_t>(runtime->stateFlags & 0x05u);
      runtime->stopTransitionPending = 1;
      CRICRS_Leave();
      return;
    }

    CRICRS_Leave();
  }

  /**
   * Address: 0x00B17C60 (FUN_00B17C60, j__ADXRNA_SetPlaySw)
   *
   * What it does:
   * Thunk wrapper to `ADXRNA_SetPlaySw`.
   */
  void j__ADXRNA_SetPlaySw(const std::int32_t rnaHandle, const std::int32_t enabled)
  {
    ADXRNA_SetPlaySw(rnaHandle, enabled);
  }

  /**
   * Address: 0x00B14720 (FUN_00B14720, _adxrna_Init)
   *
   * What it does:
   * Initializes ADXRNA global runtime pools, handler dispatch, and error callback
   * state on first init; then increments ADXRNA init reference count.
   */
  [[maybe_unused]] std::int32_t adxrna_GlobalInit()
  {
    (void)kRnaVersionBanner;

    std::int32_t result = gAdxrnaInitCount;
    if (gAdxrnaInitCount == 0) {
      crierr_default_callback();
      std::memset(gAdxrnaRuntimePool.data(), 0, sizeof(gAdxrnaRuntimePool));
      std::memset(gAdxrnaScratchStateA.data(), 0, gAdxrnaScratchStateA.size());
      std::memset(gAdxrnaScratchStateB.data(), 0x80, gAdxrnaScratchStateB.size());

      if (gAdxrnaDsoundHandler == nullptr) {
        gAdxrnaDsoundHandler = adxrna_GetDefaultDsoundHandler();
      }
      gAdxrnaDsoundHandler->initialize(gAdxrnaDirectSound8);

      adxrna_PostInitNoOpHook();
      result = CRIERR_SetCbErr(nullptr, 0);
    }

    ++gAdxrnaInitCount;
    return result;
  }

  /**
   * Address: 0x00B147B0 (FUN_00B147B0, adxrnda_finish)
   *
   * What it does:
   * Decrements ADXRNA init reference count and, on final release, stops and
   * destroys all active ADXRNA runtime objects then resets global runtime state.
   */
  [[maybe_unused]] std::int32_t adxrna_GlobalFinish()
  {
    const std::int32_t result = --gAdxrnaInitCount;
    if (gAdxrnaInitCount != 0) {
      return result;
    }

    for (auto& runtime : gAdxrnaRuntimePool) {
      if (runtime.inUse == 1u) {
        ADXRNA_Stop(static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(&runtime)));
      }
    }

    for (auto& runtime : gAdxrnaRuntimePool) {
      if (runtime.inUse == 1u) {
        (void)adxrna_DestroyCore(&runtime);
      }
    }

    std::memset(gAdxrnaRuntimePool.data(), 0, sizeof(gAdxrnaRuntimePool));
    std::memset(gAdxrnaScratchStateA.data(), 0, gAdxrnaScratchStateA.size());
    std::memset(gAdxrnaScratchStateB.data(), 0x80, gAdxrnaScratchStateB.size());

    if (gAdxrnaDsoundHandler != nullptr) {
      gAdxrnaDsoundHandler->shutdown();
    }
    adxrna_NoOpFinalizeHook();
    return 0;
  }

  /**
   * Address: 0x00B17BD0 (FUN_00B17BD0, _ADXRNA_Init)
   *
   * What it does:
   * Thunk wrapper to ADXRNA global init flow.
   */
  std::int32_t ADXRNA_Init()
  {
    return adxrna_GlobalInit();
  }

  /**
   * Address: 0x00B17BE0 (FUN_00B17BE0, _ADXRNA_Finish)
   *
   * What it does:
   * Thunk wrapper to ADXRNA global finish flow.
   */
  std::int32_t ADXRNA_Finish()
  {
    return adxrna_GlobalFinish();
  }

  /**
   * Address: 0x00B17B40 (FUN_00B17B40, _adxt_IsActiveFsSvr)
   *
   * What it does:
   * Returns whether ADXT filesystem server enter-count is non-zero.
   */
  [[maybe_unused]] BOOL adxt_IsActiveFsSvr()
  {
    return (gAdxtFsServerEnterCount != 0) ? TRUE : FALSE;
  }

  /**
   * Address: 0x00B17B50 (FUN_00B17B50, _ADXCRS_Init)
   *
   * What it does:
   * Increments ADX critical-section init count and resets lock-level lane on
   * first initialization.
   */
  [[maybe_unused]] std::int32_t ADXCRS_Init()
  {
    const std::int32_t result = ++gAdxcrsInitCount;
    if (gAdxcrsInitCount == 1) {
      gAdxcrsLevel = 0;
    }
    return result;
  }

  /**
   * Address: 0x00B17B70 (FUN_00B17B70, _ADXCRS_Finish)
   *
   * What it does:
   * Decrements ADX critical-section init count and clears lock-level lane when
   * refcount reaches zero.
   */
  [[maybe_unused]] std::int32_t ADXCRS_Finish()
  {
    const std::int32_t result = --gAdxcrsInitCount;
    if (gAdxcrsInitCount == 0) {
      gAdxcrsLevel = 0;
    }
    return result;
  }

  /**
   * Address: 0x00B17A80 (FUN_00B17A80, _adxt_ExecFsSvr)
   *
   * What it does:
   * Executes one ADXT filesystem-server tick with explicit reentry-state lanes.
   */
  void adxt_ExecFsSvr()
  {
    ADXCRS_Lock();
    if (gAdxtFsServerEnterCount != 0) {
      ADXCRS_Unlock();
      return;
    }

    gAdxtFsServerEnterCount = 1;
    ADXCRS_Unlock();

    gAdxtFsServerEnterCount = 3;
    ADXSTM_ExecFsSvr();
    gAdxtFsServerEnterCount = 4;
    ADXSTM_ExecServer();
    gAdxtFsServerEnterCount = 5;
    ADXF_ExecServer();
    gAdxtFsServerEnterCount = 6;
    ADXSTM_ExecServer();
    gAdxtFsServerEnterCount = 7;
    ADXSTM_ExecFsSvr();
    gAdxtFsServerEnterCount = 0;
  }

  /**
   * Address: 0x00B17A70 (FUN_00B17A70, _ADXT_ExecFsSvr)
   *
   * What it does:
   * Guarded wrapper around one ADXT filesystem-server execution tick.
   */
  void ADXT_ExecFsSvr()
  {
    ADXCRS_Enter();
    adxt_ExecFsSvr();
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B17B10 (FUN_00B17B10, _adxt_ExecFsServer)
   *
   * What it does:
   * Thunk wrapper to `ADXT_ExecFsSvr`.
   */
  void adxt_ExecFsServer()
  {
    ADXT_ExecFsSvr();
  }

  /**
   * Address: 0x00B17B00 (FUN_00B17B00, _ADXT_ExecFsServer)
   *
   * What it does:
   * Guarded wrapper around ADXT filesystem-server dispatcher thunk.
   */
  void ADXT_ExecFsServer()
  {
    ADXCRS_Enter();
    adxt_ExecFsServer();
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E2A0 (FUN_00B0E2A0, _ADXT_ExecServer)
   *
   * What it does:
   * Runs one ADXT decode-server tick under legacy ADX enter/leave wrappers.
   */
  void ADXT_ExecServer()
  {
    ADXCRS_Enter();
    adxt_ExecServer();
    ADXCRS_Leave();
  }

  /**
   * Address: 0x00B0E2B0 (FUN_00B0E2B0, _adxt_ExecServer)
   *
   * What it does:
   * Runs one ADXT decode-server tick with reentrancy guard and dispatches SJD,
   * per-runtime handle ticks, then RNA server.
   */
  void adxt_ExecServer()
  {
    ADXCRS_Lock();
    if (adxt_tsvr_enter_cnt != 0) {
      ADXCRS_Unlock();
      return;
    }

    adxt_tsvr_enter_cnt = 1;
    ADXCRS_Unlock();

    ADXSJD_ExecServer();

    adxt_tsvr_enter_cnt = 2;
    for (auto& runtimeSlot : gAdxtRuntimePool) {
      if (runtimeSlot.used == 1u) {
        ADXT_ExecHndl(&runtimeSlot);
      }
    }

    adxt_tsvr_enter_cnt = 3;
    ADXRNA_ExecServer();
    adxt_tsvr_enter_cnt = 0;
  }

  /**
   * Address: 0x00B17B20 (FUN_00B17B20, _ADXT_IsActiveFsSvr)
   *
   * What it does:
   * Returns ADXT filesystem-server active state under ADX enter/leave guards.
   */
  std::int32_t ADXT_IsActiveFsSvr()
  {
    ADXCRS_Enter();
    const std::int32_t activeState = static_cast<std::int32_t>(adxt_IsActiveFsSvr());
    ADXCRS_Leave();
    return activeState;
  }

  /**
   * Address: 0x00B17B90 (FUN_00B17B90, _ADXCRS_Lock)
   */
  void ADXCRS_Lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B17BA0 (FUN_00B17BA0, _ADXCRS_Unlock)
   */
  void ADXCRS_Unlock()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B17BB0 (FUN_00B17BB0, _ADXCRS_Enter)
   *
   * What it does:
   * No-op enter shim used by legacy ADX server wrappers.
   */
  void ADXCRS_Enter()
  {
  }

  /**
   * Address: 0x00B17BC0 (FUN_00B17BC0, _ADXCRS_Leave)
   *
   * What it does:
   * No-op leave shim used by legacy ADX server wrappers.
   */
  void ADXCRS_Leave()
  {
  }

  namespace
  {
    constexpr std::int32_t kSofdecSjRingBufferPoolSize = 0x300;
    constexpr std::int32_t kSofdecSjMemoryPoolSize = 0x60;
    constexpr std::int32_t kSofdecSjUnifyPoolSize = 0xC0;
    constexpr const char* kSofdecNullPointerSuffix = " : NULL pointer is specified.";
    constexpr const char* kSofdecInvalidHandleSuffix = " : Specified handle is invalid.";
    constexpr const char* kSjrBufferErrorTag = "SJRBF_Error";
    constexpr const char* kSjMemoryErrorTag = "SJMEM_Error";
    constexpr const char* kSjUnifyErrorTag = "SJUNI_Error";

    [[nodiscard]] std::int8_t* SjAddressToPointer(const std::int32_t addressWord)
    {
      return reinterpret_cast<std::int8_t*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(addressWord)));
    }

    [[nodiscard]] std::int8_t* SjChunkBuffer(moho::SjChunkRange* const chunkRange)
    {
      return SjAddressToPointer(chunkRange->bufferAddress);
    }

    [[nodiscard]] std::int32_t SjPointerToAddress(const void* const pointer)
    {
      return static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(pointer));
    }

    [[nodiscard]] std::int32_t SjFlowCounterOffset(const std::int32_t lane, const std::int32_t counterIndex)
    {
      return counterIndex + (lane * 2);
    }

    [[nodiscard]] std::int32_t SjRoundTowardZeroDivide16(const std::int32_t value)
    {
      const std::int32_t adjust = (value < 0) ? 0xF : 0;
      return (value + adjust) >> 4;
    }

    [[nodiscard]] std::int32_t AdxmComputeSpinThresholdMicroseconds(
      const std::uint32_t interval, const std::uint32_t screenHeight
    )
    {
      return static_cast<std::int32_t>((100000000u / (screenHeight + 50u)) / interval);
    }

    [[nodiscard]] std::int32_t AdxmComputeSleepMilliseconds(
      const std::uint32_t interval, const std::uint32_t screenHeight, const std::uint32_t scanline
    )
    {
      const std::uint32_t numerator = (100000u * screenHeight) - (100000u * scanline);
      return static_cast<std::int32_t>((numerator / (screenHeight + 50u)) / interval);
    }

    [[nodiscard]] std::int64_t AdxmElapsedMicroseconds(
      const LARGE_INTEGER& startCounter, const LARGE_INTEGER& endCounter, const std::int64_t frequency
    )
    {
      return (1000000LL * (endCounter.QuadPart - startCounter.QuadPart)) / frequency;
    }
  } // namespace

  /**
   * Address: 0x00B177A0 (FUN_00B177A0, _SJERR_CallErr)
   *
   * What it does:
   * Thunk wrapper to one-argument SVM error dispatch.
   */
  void SJERR_CallErr(const char* const message)
  {
    SVM_CallErr1(message);
  }

  /**
   * Address: 0x00B177B0 (FUN_00B177B0, _SJCRS_Init)
   *
   * What it does:
   * Increments SJ critical-section init count and resets level lane on first
   * initialization.
   */
  void SJCRS_Init()
  {
    ++gSjInitCount;
    if (gSjInitCount == 1) {
      gSjCriticalSectionLevel = 0;
    }
  }

  /**
   * Address: 0x00B177D0 (FUN_00B177D0, _SJCRS_Finish)
   *
   * What it does:
   * Decrements SJ critical-section init count and clears level lane when count
   * reaches zero.
   */
  std::int32_t SJCRS_Finish()
  {
    const std::int32_t result = --gSjInitCount;
    if (gSjInitCount == 0) {
      gSjCriticalSectionLevel = 0;
    }
    return result;
  }

  namespace
  {
    struct SjLegacyStatusWordBlock
    {
      std::int32_t words[5]{};
    };

    static_assert(sizeof(SjLegacyStatusWordBlock) == 0x14, "SjLegacyStatusWordBlock size must be 0x14");

    using SjLegacyQueryStatusFn = std::int32_t(__stdcall*)(void* owner, SjLegacyStatusWordBlock* outWords);

    struct SjLegacyIoDispatchTable
    {
      std::uintptr_t mUnknown00 = 0; // +0x00
      std::uintptr_t mUnknown04 = 0; // +0x04
      std::uintptr_t mUnknown08 = 0; // +0x08
      SjLegacyQueryStatusFn queryStatus = nullptr; // +0x0C
    };

    static_assert(
      offsetof(SjLegacyIoDispatchTable, queryStatus) == 0x0C,
      "SjLegacyIoDispatchTable::queryStatus offset must be 0x0C"
    );

    struct SjLegacyIoOwnerView
    {
      SjLegacyIoDispatchTable* dispatchTable = nullptr; // +0x00
    };

    struct SjLegacyIoClientView
    {
      std::uint8_t mUnknown00_07[0x08]{}; // +0x00
      SjLegacyIoOwnerView* ioOwner = nullptr; // +0x08
    };

    static_assert(offsetof(SjLegacyIoClientView, ioOwner) == 0x08, "SjLegacyIoClientView::ioOwner offset must be 0x08");
  } // namespace

  /**
   * Address: 0x00B17730 (FUN_00B17730, sub_B17730)
   *
   * What it does:
   * Queries one SJ runtime status block through owner dispatch and returns
   * success/failure as `0/-1`.
   */
  [[maybe_unused]] std::int32_t sj_QueryLegacyIoStatus(const std::int32_t ioClientAddress)
  {
    auto* const client = reinterpret_cast<SjLegacyIoClientView*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(ioClientAddress))
    );

    SjLegacyStatusWordBlock statusWords{};
    if (client->ioOwner->dispatchTable->queryStatus(client->ioOwner, &statusWords) >= 0) {
      return 0;
    }
    return -1;
  }

  /**
   * Address: 0x00B17720 (FUN_00B17720, sub_B17720)
   *
   * What it does:
   * Returns global Sofdec buffer-placement mode lane.
   */
  [[maybe_unused]] std::int32_t SofdecGetBufferPlacementMode()
  {
    return gSofdecBufferPlacementMode;
  }

  /**
   * Address: 0x00B177F0 (FUN_00B177F0, _SJCRS_Lock)
   */
  void SJCRS_Lock()
  {
    SVM_Lock();
  }

  /**
   * Address: 0x00B17800 (FUN_00B17800, _SJCRS_Unlock)
   */
  void SJCRS_Unlock()
  {
    SVM_Unlock();
  }

  /**
   * Address: 0x00B07CA0 (FUN_00B07CA0, _SJRBF_Error)
   */
  void SJRBF_Error(const std::int32_t, const std::int32_t)
  {
    SJERR_CallErr(kSjrBufferErrorTag);
  }

  /**
   * Address: 0x00B07CB0 (FUN_00B07CB0, _SJRBF_Init)
   */
  void SJRBF_Init()
  {
    SJCRS_Init();
    SJCRS_Lock();
    (void)sjrbf_Init();
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07CD0 (FUN_00B07CD0, _sjrbf_Init)
   */
  std::int32_t sjrbf_Init()
  {
    const std::int32_t previousCount = gSofdecSjRingBufferInitCount;
    if (previousCount == 0) {
      std::memset(gSofdecSjRingBufferPool, 0, sizeof(gSofdecSjRingBufferPool));
    }

    ++gSofdecSjRingBufferInitCount;
    return previousCount;
  }

  /**
   * Address: 0x00B07CF0 (FUN_00B07CF0, _SJRBF_Finish)
   */
  std::int32_t SJRBF_Finish()
  {
    SJCRS_Lock();
    (void)sjrbf_Finish();
    SJCRS_Unlock();
    return SJCRS_Finish();
  }

  /**
   * Address: 0x00B07D10 (FUN_00B07D10, _sjrbf_Finish)
   */
  std::int32_t sjrbf_Finish()
  {
    const std::int32_t nextCount = --gSofdecSjRingBufferInitCount;
    if (nextCount == 0) {
      std::memset(gSofdecSjRingBufferPool, 0, sizeof(gSofdecSjRingBufferPool));
      return 0;
    }

    return nextCount;
  }

  /**
   * Address: 0x00B07D30 (FUN_00B07D30, _SJRBF_Create)
   */
  moho::SofdecSjRingBufferHandle* SJRBF_Create(
    const std::int32_t bufferAddress, const std::int32_t bufferSize, const std::int32_t extraSize
  )
  {
    SJCRS_Lock();
    moho::SofdecSjRingBufferHandle* const handle = sjrbf_Create(bufferAddress, bufferSize, extraSize);
    SJCRS_Unlock();
    return handle;
  }

  /**
   * Address: 0x00B07D60 (FUN_00B07D60, _sjrbf_Create)
   */
  moho::SofdecSjRingBufferHandle* sjrbf_Create(
    const std::int32_t bufferAddress, const std::int32_t bufferSize, const std::int32_t extraSize
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < kSofdecSjRingBufferPoolSize) {
      if (gSofdecSjRingBufferPool[slotIndex].used == 0) {
        break;
      }
      ++slotIndex;
    }

    if (slotIndex == kSofdecSjRingBufferPoolSize) {
      return nullptr;
    }

    moho::SofdecSjRingBufferHandle* const handle = &gSofdecSjRingBufferPool[slotIndex];
    handle->used = 1;
    handle->runtimeSlot = SjPointerToAddress(&gSofdecSjRingBufferVtableTag);
    handle->bufferBase = SjAddressToPointer(bufferAddress);
    handle->bufferSize = bufferSize;
    handle->extraSize = extraSize;
    handle->uuid = SjPointerToAddress(&gSofdecSjRingBufferUuidTag);
    handle->errFunc = SJRBF_Error;
    handle->errObj = SjPointerToAddress(handle);
    (void)sjrbf_Reset(handle);
    return handle;
  }

  /**
   * Address: 0x00B07DD0 (FUN_00B07DD0, _SJRBF_Destroy)
   */
  void SJRBF_Destroy(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    sjrbf_Destroy(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07E40 (FUN_00B07E40, _SJRBF_CallErr_)
   */
  void SJRBF_CallErr_(const char* const errorCode, const char* const errorText)
  {
    char message[64]{};
    std::strcpy(message, errorCode);
    std::strcat(message, errorText);
    SJERR_CallErr(message);
  }

  /**
   * Address: 0x00B07DF0 (FUN_00B07DF0, _sjrbf_Destroy)
   */
  void sjrbf_Destroy(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        std::memset(handle, 0, sizeof(*handle));
        handle->used = 0;
      } else {
        SJRBF_CallErr_("E2004090202", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090201", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B07EC0 (FUN_00B07EC0, _sjrbf_GetUuid)
   */
  std::int32_t sjrbf_GetUuid(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->uuid;
      }

      SJRBF_CallErr_("E2004090204", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090203", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B07EA0 (FUN_00B07EA0, _SJRBF_GetUuid)
   */
  std::int32_t SJRBF_GetUuid(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t uuid = sjrbf_GetUuid(handle);
    SJCRS_Unlock();
    return uuid;
  }

  /**
   * Address: 0x00B07F30 (FUN_00B07F30, _sjrbf_EntryErrFunc)
   */
  void sjrbf_EntryErrFunc(
    moho::SofdecSjRingBufferHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->errFunc = errorHandler;
        handle->errObj = errorObject;
      } else {
        SJRBF_CallErr_("E2004090206", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090205", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B07F00 (FUN_00B07F00, _SJRBF_EntryErrFunc)
   */
  void SJRBF_EntryErrFunc(
    moho::SofdecSjRingBufferHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    SJCRS_Lock();
    sjrbf_EntryErrFunc(handle, errorHandler, errorObject);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07F80 (FUN_00B07F80, _SJRBF_Reset)
   */
  void SJRBF_Reset(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    (void)sjrbf_Reset(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B07FA0 (FUN_00B07FA0, _sjrbf_Reset)
   */
  moho::SofdecSjRingBufferHandle* sjrbf_Reset(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090207", kSofdecNullPointerSuffix);
      return nullptr;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090208", kSofdecInvalidHandleSuffix);
      return handle;
    }

    handle->pendingLane1Bytes = 0;
    handle->pendingLane0Bytes = handle->bufferSize;
    handle->lane0Cursor = 0;
    handle->lane1Cursor = 0;
    handle->flowCounters[0] = 0;
    handle->flowCounters[1] = 0;
    handle->flowCounters[2] = 0;
    handle->flowCounters[3] = 0;
    return handle;
  }

  /**
   * Address: 0x00B08000 (FUN_00B08000, _SJRBF_GetNumData)
   */
  std::int32_t SJRBF_GetNumData(moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t value = sjrbf_GetNumData(handle, lane);
    SJCRS_Unlock();
    return value;
  }

  /**
   * Address: 0x00B08030 (FUN_00B08030, _sjrbf_GetNumData)
   */
  std::int32_t sjrbf_GetNumData(moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        if (lane == 1) {
          return handle->pendingLane1Bytes;
        }
        if (lane == 0) {
          return handle->pendingLane0Bytes;
        }

        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
        return 0;
      }

      SJRBF_CallErr_("E2004090210", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090209", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B080A0 (FUN_00B080A0, _SJRBF_GetChunk)
   */
  void SJRBF_GetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    SJCRS_Lock();
    sjrbf_GetChunk(handle, lane, requestedBytes, outChunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B080D0 (FUN_00B080D0, _sjrbf_GetChunk)
   */
  void sjrbf_GetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090211", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090212", kSofdecInvalidHandleSuffix);
      return;
    }
    if (handle->bufferSize == 0) {
      SJRBF_CallErr_("E2004090219", " : Illegal buffer size.");
      return;
    }

    if (lane == 0) {
      std::int32_t readableBytes = handle->bufferSize + handle->extraSize - handle->lane0Cursor;
      if (handle->pendingLane0Bytes < readableBytes) {
        readableBytes = handle->pendingLane0Bytes;
      }

      std::int32_t grantedBytes = requestedBytes;
      outChunkRange->byteCount = readableBytes;
      if (readableBytes < grantedBytes) {
        grantedBytes = readableBytes;
      }

      outChunkRange->byteCount = grantedBytes;
      outChunkRange->bufferAddress = SjPointerToAddress(handle->bufferBase + handle->lane0Cursor);
      handle->lane0Cursor = (handle->lane0Cursor + grantedBytes) % handle->bufferSize;
      handle->pendingLane0Bytes -= outChunkRange->byteCount;
      handle->flowCounters[SjFlowCounterOffset(0, 0)] += outChunkRange->byteCount;
      return;
    }

    if (lane == 1) {
      std::int32_t readableBytes = handle->bufferSize + handle->extraSize - handle->lane1Cursor;
      if (handle->pendingLane1Bytes < readableBytes) {
        readableBytes = handle->pendingLane1Bytes;
      }

      std::int32_t grantedBytes = requestedBytes;
      outChunkRange->byteCount = readableBytes;
      if (readableBytes < grantedBytes) {
        grantedBytes = readableBytes;
      }

      outChunkRange->byteCount = grantedBytes;
      outChunkRange->bufferAddress = SjPointerToAddress(handle->bufferBase + handle->lane1Cursor);
      handle->lane1Cursor = (handle->lane1Cursor + grantedBytes) % handle->bufferSize;
      handle->pendingLane1Bytes -= outChunkRange->byteCount;
      handle->flowCounters[SjFlowCounterOffset(1, 0)] += outChunkRange->byteCount;
      return;
    }

    outChunkRange->byteCount = 0;
    outChunkRange->bufferAddress = 0;
    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B08210 (FUN_00B08210, _SJRBF_PutChunk)
   */
  void SJRBF_PutChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjrbf_PutChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B08240 (FUN_00B08240, _sjrbf_PutChunk)
   */
  void sjrbf_PutChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        const std::int32_t chunkBytes = chunkRange->byteCount;
        if (chunkBytes > 0) {
          std::int8_t* const chunkBuffer = SjChunkBuffer(chunkRange);
          if (chunkBuffer != nullptr) {
            if (lane == 1) {
              const std::int32_t extraSize = handle->extraSize;
              const std::int32_t relativeStart =
                SjPointerToAddress(chunkBuffer) - SjPointerToAddress(handle->bufferBase);
              if (relativeStart < extraSize) {
                std::int32_t mirroredBytes = extraSize - relativeStart;
                if (chunkBytes < mirroredBytes) {
                  mirroredBytes = chunkBytes;
                }
                std::memcpy(
                  chunkBuffer + handle->bufferSize, chunkBuffer, static_cast<std::size_t>(mirroredBytes)
                );
              }

              std::int32_t spillCopyBytes = chunkBytes;
              const std::int32_t relativeEnd = relativeStart + spillCopyBytes;
              if (relativeEnd > handle->bufferSize) {
                const std::int32_t requiredBytes = relativeEnd - handle->bufferSize;
                if (spillCopyBytes >= requiredBytes) {
                  spillCopyBytes = requiredBytes;
                }
                std::memcpy(
                  handle->bufferBase,
                  chunkBuffer + (chunkBytes - spillCopyBytes),
                  static_cast<std::size_t>(spillCopyBytes)
                );
              }

              handle->pendingLane1Bytes += chunkBytes;
              handle->flowCounters[3] += chunkBytes;
              return;
            }

            if (lane != 0) {
              chunkRange->byteCount = 0;
              chunkRange->bufferAddress = 0;
              if (handle->errFunc != nullptr) {
                handle->errFunc(handle->errObj, -3);
              }
              return;
            }

            handle->pendingLane0Bytes += chunkBytes;
            handle->flowCounters[1] += chunkBytes;
          }
        }
      } else {
        SJRBF_CallErr_("E2004090214", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090213", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B08360 (FUN_00B08360, _SJRBF_UngetChunk)
   */
  void SJRBF_UngetChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjrbf_UngetChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B08390 (FUN_00B08390, _sjrbf_UngetChunk)
   */
  void sjrbf_UngetChunk(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090215", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090216", kSofdecInvalidHandleSuffix);
      return;
    }
    if (handle->bufferSize == 0) {
      SJRBF_CallErr_("E2004090220", " : Illegal buffer size.");
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    const std::int32_t chunkAddress = chunkRange->bufferAddress;
    if (chunkAddress == 0) {
      return;
    }

    if (lane == 0) {
      const std::int32_t expectedCursor = (chunkAddress - SjPointerToAddress(handle->bufferBase)) % handle->bufferSize;
      const std::int32_t rewindCursor = (handle->bufferSize + handle->lane0Cursor - chunkBytes) % handle->bufferSize;
      if (rewindCursor == expectedCursor) {
        handle->lane0Cursor = rewindCursor;
        handle->pendingLane0Bytes += chunkBytes;
        handle->flowCounters[SjFlowCounterOffset(0, 0)] -= chunkBytes;
      } else {
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
        handle->flowCounters[SjFlowCounterOffset(0, 0)] -= chunkBytes;
      }
      return;
    }

    if (lane == 1) {
      const std::int32_t expectedCursor = (chunkAddress - SjPointerToAddress(handle->bufferBase)) % handle->bufferSize;
      const std::int32_t rewindCursor = (handle->bufferSize + handle->lane1Cursor - chunkBytes) % handle->bufferSize;
      if (rewindCursor == expectedCursor) {
        handle->lane1Cursor = rewindCursor;
        handle->pendingLane1Bytes += chunkBytes;
        handle->flowCounters[SjFlowCounterOffset(1, 0)] -= chunkBytes;
      } else {
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
        handle->flowCounters[SjFlowCounterOffset(1, 0)] -= chunkBytes;
      }
      return;
    }

    chunkRange->byteCount = 0;
    chunkRange->bufferAddress = 0;
    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B084F0 (FUN_00B084F0, _SJRBF_IsGetChunk)
   */
  std::int32_t SJRBF_IsGetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    SJCRS_Lock();
    const std::int32_t canGet = sjrbf_IsGetChunk(handle, lane, requestedBytes, outGrantedBytes);
    SJCRS_Unlock();
    return canGet;
  }

  /**
   * Address: 0x00B08520 (FUN_00B08520, _sjrbf_IsGetChunk)
   */
  std::int32_t sjrbf_IsGetChunk(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    if (handle == nullptr) {
      SJRBF_CallErr_("E2004090217", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJRBF_CallErr_("E2004090218", kSofdecInvalidHandleSuffix);
      return 0;
    }

    std::int32_t grantedBytes = 0;
    if (lane != 0) {
      if (lane == 1) {
        grantedBytes = handle->pendingLane1Bytes;
        const std::int32_t maxReadableBytes = handle->bufferSize + handle->extraSize - handle->lane1Cursor;
        if (grantedBytes >= maxReadableBytes) {
          grantedBytes = maxReadableBytes;
        }
        if (grantedBytes >= requestedBytes) {
          *outGrantedBytes = requestedBytes;
          return 1;
        }
      } else {
        grantedBytes = 0;
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
      }
    } else {
      grantedBytes = handle->pendingLane0Bytes;
      const std::int32_t maxReadableBytes = handle->bufferSize + handle->extraSize - handle->lane0Cursor;
      if (grantedBytes >= maxReadableBytes) {
        grantedBytes = maxReadableBytes;
      }
      if (grantedBytes >= requestedBytes) {
        *outGrantedBytes = requestedBytes;
        return 1;
      }
    }

    *outGrantedBytes = grantedBytes;
    return (grantedBytes == requestedBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00B085F0 (FUN_00B085F0, _SJRBF_GetBufPtr)
   */
  std::int32_t SJRBF_GetBufPtr(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferAddress = sjrbf_GetBufPtr(handle);
    SJCRS_Unlock();
    return bufferAddress;
  }

  /**
   * Address: 0x00B08610 (FUN_00B08610, _sjrbf_GetBufPtr)
   */
  std::int32_t sjrbf_GetBufPtr(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return SjPointerToAddress(handle->bufferBase);
      }

      SJRBF_CallErr_("E2004090222", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090221", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B08650 (FUN_00B08650, _SJRBF_GetBufSize)
   */
  std::int32_t SJRBF_GetBufSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferSize = sjrbf_GetBufSize(handle);
    SJCRS_Unlock();
    return bufferSize;
  }

  /**
   * Address: 0x00B08670 (FUN_00B08670, _sjrbf_GetBufSize)
   */
  std::int32_t sjrbf_GetBufSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->bufferSize;
      }

      SJRBF_CallErr_("E2004090224", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090223", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B086B0 (FUN_00B086B0, _SJRBF_GetXtrSize)
   */
  std::int32_t SJRBF_GetXtrSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t extraSize = sjrbf_GetXtrSize(handle);
    SJCRS_Unlock();
    return extraSize;
  }

  /**
   * Address: 0x00B086D0 (FUN_00B086D0, _sjrbf_GetXtrSize)
   */
  std::int32_t sjrbf_GetXtrSize(moho::SofdecSjRingBufferHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->extraSize;
      }

      SJRBF_CallErr_("E2004090226", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090225", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B08710 (FUN_00B08710, _SJRBF_SetFlowCnt)
   */
  void SJRBF_SetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t counterIndex,
    const std::int32_t value
  )
  {
    SJCRS_Lock();
    sjrbf_SetFlowCnt(handle, lane, counterIndex, value);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B08740 (FUN_00B08740, _sjrbf_SetFlowCnt)
   */
  void sjrbf_SetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle,
    const std::int32_t lane,
    const std::int32_t counterIndex,
    const std::int32_t value
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->flowCounters[SjFlowCounterOffset(lane, counterIndex)] = value;
      } else {
        SJRBF_CallErr_("E2004090228", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJRBF_CallErr_("E2004090227", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B08790 (FUN_00B08790, _SJRBF_GetFlowCnt)
   */
  std::int32_t SJRBF_GetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, const std::int32_t counterIndex
  )
  {
    SJCRS_Lock();
    const std::int32_t value = sjrbf_GetFlowCnt(handle, lane, counterIndex);
    SJCRS_Unlock();
    return value;
  }

  /**
   * Address: 0x00B087C0 (FUN_00B087C0, _sjrbf_GetFlowCnt)
   */
  std::int32_t sjrbf_GetFlowCnt(
    moho::SofdecSjRingBufferHandle* const handle, const std::int32_t lane, const std::int32_t counterIndex
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->flowCounters[SjFlowCounterOffset(lane, counterIndex)];
      }

      SJRBF_CallErr_("E2004090230", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJRBF_CallErr_("E2004090229", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09030 (FUN_00B09030, _SJMEM_Error)
   */
  void SJMEM_Error(const std::int32_t, const std::int32_t)
  {
    SJERR_CallErr(kSjMemoryErrorTag);
  }

  /**
   * Address: 0x00B09040 (FUN_00B09040, _SJMEM_Init)
   */
  void SJMEM_Init()
  {
    SJCRS_Init();
    SJCRS_Lock();
    (void)sjmem_Init();
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09060 (FUN_00B09060, _sjmem_Init)
   */
  std::int32_t sjmem_Init()
  {
    const std::int32_t previousCount = gSofdecSjMemoryInitCount;
    if (previousCount == 0) {
      std::memset(gSofdecSjMemoryPool, 0, sizeof(gSofdecSjMemoryPool));
    }

    ++gSofdecSjMemoryInitCount;
    return previousCount;
  }

  /**
   * Address: 0x00B09080 (FUN_00B09080, _SJMEM_Finish)
   */
  std::int32_t SJMEM_Finish()
  {
    SJCRS_Lock();
    (void)sjmem_Finish();
    SJCRS_Unlock();
    return SJCRS_Finish();
  }

  /**
   * Address: 0x00B090A0 (FUN_00B090A0, _sjmem_Finish)
   */
  std::int32_t sjmem_Finish()
  {
    const std::int32_t nextCount = --gSofdecSjMemoryInitCount;
    if (nextCount == 0) {
      std::memset(gSofdecSjMemoryPool, 0, sizeof(gSofdecSjMemoryPool));
      return 0;
    }

    return nextCount;
  }

  /**
   * Address: 0x00B090C0 (FUN_00B090C0, _SJMEM_Create)
   */
  moho::SofdecSjMemoryHandle* SJMEM_Create(const std::int32_t bufferAddress, const std::int32_t bufferSize)
  {
    SJCRS_Lock();
    moho::SofdecSjMemoryHandle* const handle = sjmem_Create(bufferAddress, bufferSize);
    SJCRS_Unlock();
    return handle;
  }

  /**
   * Address: 0x00B090F0 (FUN_00B090F0, _sjmem_Create)
   */
  moho::SofdecSjMemoryHandle* sjmem_Create(const std::int32_t bufferAddress, const std::int32_t bufferSize)
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < kSofdecSjMemoryPoolSize) {
      if (gSofdecSjMemoryPool[slotIndex].used == 0) {
        break;
      }
      ++slotIndex;
    }

    if (slotIndex == kSofdecSjMemoryPoolSize) {
      return nullptr;
    }

    moho::SofdecSjMemoryHandle* const handle = &gSofdecSjMemoryPool[slotIndex];
    handle->used = 1;
    handle->runtimeSlot = SjPointerToAddress(&gSofdecSjMemoryVtableTag);
    handle->produceOffset = bufferAddress;
    handle->bufferSize = bufferSize;
    handle->uuid = SjPointerToAddress(&gSofdecSjMemoryUuidTag);
    handle->errFunc = SJMEM_Error;
    handle->errObj = SjPointerToAddress(handle);
    (void)sjmem_Reset(handle);
    return handle;
  }

  /**
   * Address: 0x00B091D0 (FUN_00B091D0, _SJMEM_CallErr_)
   */
  void SJMEM_CallErr_(const char* const errorCode, const char* const errorText)
  {
    char message[64]{};
    std::strcpy(message, errorCode);
    std::strcat(message, errorText);
    SJERR_CallErr(message);
  }

  /**
   * Address: 0x00B09180 (FUN_00B09180, _sjmem_Destroy)
   */
  std::int32_t sjmem_Destroy(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090231", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090232", kSofdecInvalidHandleSuffix);
      return 0;
    }

    std::memset(handle, 0, sizeof(*handle));
    handle->used = 0;
    return 0;
  }

  /**
   * Address: 0x00B09160 (FUN_00B09160, _SJMEM_Destroy)
   */
  void SJMEM_Destroy(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    (void)sjmem_Destroy(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09250 (FUN_00B09250, _sjmem_GetUuid)
   */
  std::int32_t sjmem_GetUuid(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->uuid;
      }

      SJMEM_CallErr_("E2004090234", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090233", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09230 (FUN_00B09230, _SJMEM_GetUuid)
   */
  std::int32_t SJMEM_GetUuid(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t uuid = sjmem_GetUuid(handle);
    SJCRS_Unlock();
    return uuid;
  }

  /**
   * Address: 0x00B092C0 (FUN_00B092C0, _sjmem_EntryErrFunc)
   */
  void sjmem_EntryErrFunc(
    moho::SofdecSjMemoryHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->errFunc = errorHandler;
        handle->errObj = errorObject;
      } else {
        SJMEM_CallErr_("E2004090236", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJMEM_CallErr_("E2004090235", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09290 (FUN_00B09290, _SJMEM_EntryErrFunc)
   */
  void SJMEM_EntryErrFunc(
    moho::SofdecSjMemoryHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    SJCRS_Lock();
    sjmem_EntryErrFunc(handle, errorHandler, errorObject);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09310 (FUN_00B09310, _SJMEM_Reset)
   */
  void SJMEM_Reset(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    (void)sjmem_Reset(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09330 (FUN_00B09330, _sjmem_Reset)
   */
  moho::SofdecSjMemoryHandle* sjmem_Reset(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090237", kSofdecNullPointerSuffix);
      return nullptr;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090238", kSofdecInvalidHandleSuffix);
      return handle;
    }

    handle->consumeOffset = 0;
    handle->pendingBytes = handle->bufferSize;
    return handle;
  }

  /**
   * Address: 0x00B09380 (FUN_00B09380, _SJMEM_GetNumData)
   *
   * What it does:
   * Lock-wrapper that queries one SJMEM lane readable-byte count.
   */
  std::int32_t SJMEM_GetNumData(moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t readableBytes = sjmem_GetNumData(handle, lane);
    SJCRS_Unlock();
    return readableBytes;
  }

  /**
   * Address: 0x00B093B0 (FUN_00B093B0, _sjmem_GetNumData)
   *
   * What it does:
   * Returns lane-1 readable bytes (`pendingBytes`); lane 0 reports empty.
   */
  std::int32_t sjmem_GetNumData(moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        if (lane == 1) {
          return handle->pendingBytes;
        }

        if (lane != 0) {
          if (handle->errFunc != nullptr) {
            handle->errFunc(handle->errObj, -3);
          }
        }
        return 0;
      }

      SJMEM_CallErr_("E2004090240", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090239", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09410 (FUN_00B09410, _SJMEM_GetChunk)
   *
   * What it does:
   * Lock-wrapper that fetches one SJMEM chunk descriptor.
   */
  void SJMEM_GetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    SJCRS_Lock();
    sjmem_GetChunk(handle, lane, requestedBytes, outChunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09440 (FUN_00B09440, _sjmem_GetChunk)
   *
   * What it does:
   * Emits chunk range for lane `1` and advances SJMEM read state.
   */
  void sjmem_GetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090241", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090242", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane == 0) {
      outChunkRange->byteCount = 0;
      outChunkRange->bufferAddress = 0;
      return;
    }

    if (lane == 1) {
      std::int32_t grantedBytes = handle->pendingBytes;
      if (grantedBytes >= requestedBytes) {
        grantedBytes = requestedBytes;
      }

      outChunkRange->byteCount = grantedBytes;
      outChunkRange->bufferAddress = handle->consumeOffset + handle->produceOffset;
      handle->consumeOffset += grantedBytes;
      handle->pendingBytes -= outChunkRange->byteCount;
      return;
    }

    outChunkRange->byteCount = 0;
    outChunkRange->bufferAddress = 0;
    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B094E0 (FUN_00B094E0, _SJMEM_PutChunk)
   *
   * What it does:
   * Lock-wrapper for SJMEM put-chunk validation semantics.
   */
  void SJMEM_PutChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjmem_PutChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09510 (FUN_00B09510, _sjmem_PutChunk)
   *
   * What it does:
   * Rejects non-supported SJMEM lanes when chunk data is non-empty.
   */
  void sjmem_PutChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        if (chunkRange->byteCount > 0 && chunkRange->bufferAddress != 0) {
          if (lane != 0 && lane != 1) {
            chunkRange->byteCount = 0;
            chunkRange->bufferAddress = 0;
            if (handle->errFunc != nullptr) {
              handle->errFunc(handle->errObj, -3);
            }
          }
        }
      } else {
        SJMEM_CallErr_("E2004090244", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJMEM_CallErr_("E2004090243", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09590 (FUN_00B09590, _SJMEM_UngetChunk)
   *
   * What it does:
   * Lock-wrapper that attempts to rewind one SJMEM chunk.
   */
  void SJMEM_UngetChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjmem_UngetChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B095C0 (FUN_00B095C0, _sjmem_UngetChunk)
   *
   * What it does:
   * Rewinds lane `1` if chunk origin matches expected read cursor.
   */
  void sjmem_UngetChunk(
    moho::SofdecSjMemoryHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090245", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090246", kSofdecInvalidHandleSuffix);
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    if (chunkRange->bufferAddress == 0) {
      return;
    }

    if (lane == 1) {
      std::int32_t rewindOffset = handle->consumeOffset - chunkBytes;
      if (rewindOffset <= 0) {
        rewindOffset = 0;
      }
      handle->consumeOffset = rewindOffset;

      std::int32_t readableBytes = handle->pendingBytes + chunkBytes;
      if (handle->bufferSize < readableBytes) {
        readableBytes = handle->bufferSize;
      }
      handle->pendingBytes = readableBytes;

      const std::int32_t expectedOffset = chunkRange->bufferAddress - handle->produceOffset;
      if (rewindOffset != expectedOffset) {
        if (handle->errFunc != nullptr) {
          handle->errFunc(handle->errObj, -3);
        }
      }
      return;
    }

    if (lane != 0) {
      chunkRange->byteCount = 0;
      chunkRange->bufferAddress = 0;
    }

    if (handle->errFunc != nullptr) {
      handle->errFunc(handle->errObj, -3);
    }
  }

  /**
   * Address: 0x00B09680 (FUN_00B09680, _SJMEM_IsGetChunk)
   *
   * What it does:
   * Lock-wrapper that checks SJMEM chunk availability.
   */
  std::int32_t SJMEM_IsGetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    SJCRS_Lock();
    const std::int32_t available = sjmem_IsGetChunk(handle, lane, requestedBytes, outGrantedBytes);
    SJCRS_Unlock();
    return available;
  }

  /**
   * Address: 0x00B096B0 (FUN_00B096B0, _sjmem_IsGetChunk)
   *
   * What it does:
   * Writes granted-byte count and returns whether request can be satisfied.
   */
  std::int32_t sjmem_IsGetChunk(
    moho::SofdecSjMemoryHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    if (handle == nullptr) {
      SJMEM_CallErr_("E2004090247", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJMEM_CallErr_("E2004090248", kSofdecInvalidHandleSuffix);
      return 0;
    }

    if (lane == 0) {
      *outGrantedBytes = 0;
      return (requestedBytes == 0) ? 1 : 0;
    }

    std::int32_t grantedBytes = 0;
    if (lane == 1) {
      grantedBytes = handle->pendingBytes;
      if (grantedBytes >= requestedBytes) {
        *outGrantedBytes = requestedBytes;
        return 1;
      }
    } else {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
    }

    *outGrantedBytes = grantedBytes;
    return (grantedBytes == requestedBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00B09760 (FUN_00B09760, _SJMEM_GetBufPtr)
   *
   * What it does:
   * Lock-wrapper returning SJMEM base buffer address lane.
   */
  std::int32_t SJMEM_GetBufPtr(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferAddress = sjmem_GetBufPtr(handle);
    SJCRS_Unlock();
    return bufferAddress;
  }

  /**
   * Address: 0x00B09780 (FUN_00B09780, _sjmem_GetBufPtr)
   *
   * What it does:
   * Returns configured SJMEM base buffer address for one valid handle.
   */
  std::int32_t sjmem_GetBufPtr(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->produceOffset;
      }

      SJMEM_CallErr_("E2004090250", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090249", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B097C0 (FUN_00B097C0, _SJMEM_GetBufSize)
   *
   * What it does:
   * Lock-wrapper returning SJMEM buffer size lane.
   */
  std::int32_t SJMEM_GetBufSize(moho::SofdecSjMemoryHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t bufferSize = sjmem_GetBufSize(handle);
    SJCRS_Unlock();
    return bufferSize;
  }

  /**
   * Address: 0x00B097E0 (FUN_00B097E0, _sjmem_GetBufSize)
   *
   * What it does:
   * Returns configured SJMEM buffer size for one valid handle.
   */
  std::int32_t sjmem_GetBufSize(moho::SofdecSjMemoryHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->bufferSize;
      }

      SJMEM_CallErr_("E2004090252", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJMEM_CallErr_("E2004090251", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09960 (FUN_00B09960, _SJUNI_Error)
   */
  void SJUNI_Error(const std::int32_t, const std::int32_t)
  {
    SJERR_CallErr(kSjUnifyErrorTag);
  }

  /**
   * Address: 0x00B09970 (FUN_00B09970, _SJUNI_Init)
   */
  void SJUNI_Init()
  {
    SJCRS_Init();
    SJCRS_Lock();
    (void)sjuni_Init();
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09990 (FUN_00B09990, _sjuni_Init)
   */
  std::int32_t sjuni_Init()
  {
    const std::int32_t previousCount = gSofdecSjUnifyInitCount;
    if (previousCount == 0) {
      std::memset(gSofdecSjUnifyPool, 0, sizeof(gSofdecSjUnifyPool));
    }
    ++gSofdecSjUnifyInitCount;
    return previousCount;
  }

  /**
   * Address: 0x00B099B0 (FUN_00B099B0, _SJUNI_Finish)
   */
  std::int32_t SJUNI_Finish()
  {
    SJCRS_Lock();
    (void)sjuni_Finish();
    SJCRS_Unlock();
    return SJCRS_Finish();
  }

  /**
   * Address: 0x00B099D0 (FUN_00B099D0, _sjuni_Finish)
   */
  std::int32_t sjuni_Finish()
  {
    const std::int32_t nextCount = --gSofdecSjUnifyInitCount;
    if (nextCount == 0) {
      std::memset(gSofdecSjUnifyPool, 0, sizeof(gSofdecSjUnifyPool));
      return 0;
    }
    return nextCount;
  }

  /**
   * Address: 0x00B099F0 (FUN_00B099F0, _SJUNI_Create)
   */
  moho::SofdecSjUnifyHandle* SJUNI_Create(
    const std::uint8_t mergeAdjacentChunks, const std::int32_t chainPoolAddress, const std::int32_t chainPoolBytes
  )
  {
    SJCRS_Lock();
    moho::SofdecSjUnifyHandle* const handle = sjuni_Create(mergeAdjacentChunks, chainPoolAddress, chainPoolBytes);
    SJCRS_Unlock();
    return handle;
  }

  /**
   * Address: 0x00B09A20 (FUN_00B09A20, _sjuni_Create)
   */
  moho::SofdecSjUnifyHandle* sjuni_Create(
    const std::uint8_t mergeAdjacentChunks, const std::int32_t chainPoolAddress, const std::int32_t chainPoolBytes
  )
  {
    std::int32_t slotIndex = 0;
    while (slotIndex < kSofdecSjUnifyPoolSize) {
      if (gSofdecSjUnifyPool[slotIndex].used == 0) {
        break;
      }
      ++slotIndex;
    }

    if (slotIndex == kSofdecSjUnifyPoolSize) {
      return nullptr;
    }

    moho::SofdecSjUnifyHandle* const handle = &gSofdecSjUnifyPool[slotIndex];
    handle->mergeAdjacentChunks = mergeAdjacentChunks;
    handle->used = 1;
    handle->runtimeSlot = SjPointerToAddress(&gSofdecSjUnifyVtableTag);
    handle->uuid = SjPointerToAddress(&gSofdecSjUnifyUuidTag);
    handle->chainPoolBase = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(SjAddressToPointer(chainPoolAddress));
    handle->chainPoolCount = SjRoundTowardZeroDivide16(chainPoolBytes);
    handle->errFunc = SJUNI_Error;
    handle->errObj = SjPointerToAddress(handle);
    sjuni_Reset(handle);
    return handle;
  }

  /**
   * Address: 0x00B09AA0 (FUN_00B09AA0, _SJUNI_Destroy)
   */
  void SJUNI_Destroy(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    sjuni_Destroy(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09AC0 (FUN_00B09AC0, _sjuni_Destroy)
   */
  void sjuni_Destroy(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        std::memset(handle, 0, sizeof(*handle));
        handle->used = 0;
      } else {
        SJUNI_CallErr_("E2004090262", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJUNI_CallErr_("E2004090261", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09B10 (FUN_00B09B10, _SJUNI_CallErr_)
   */
  void SJUNI_CallErr_(const char* const errorCode, const char* const errorText)
  {
    char message[64]{};
    std::strcpy(message, errorCode);
    std::strcat(message, errorText);
    SJERR_CallErr(message);
  }

  /**
   * Address: 0x00B09B70 (FUN_00B09B70, _SJUNI_GetUuid)
   */
  std::int32_t SJUNI_GetUuid(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t uuid = sjuni_GetUuid(handle);
    SJCRS_Unlock();
    return uuid;
  }

  /**
   * Address: 0x00B09B90 (FUN_00B09B90, _sjuni_GetUuid)
   */
  std::int32_t sjuni_GetUuid(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        return handle->uuid;
      }

      SJUNI_CallErr_("E2004090264", kSofdecInvalidHandleSuffix);
      return 0;
    }

    SJUNI_CallErr_("E2004090263", kSofdecNullPointerSuffix);
    return 0;
  }

  /**
   * Address: 0x00B09BD0 (FUN_00B09BD0, _SJUNI_EntryErrFunc)
   */
  void SJUNI_EntryErrFunc(
    moho::SofdecSjUnifyHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    SJCRS_Lock();
    sjuni_EntryErrFunc(handle, errorHandler, errorObject);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09C00 (FUN_00B09C00, _sjuni_EntryErrFunc)
   */
  void sjuni_EntryErrFunc(
    moho::SofdecSjUnifyHandle* const handle,
    const moho::SofdecErrorHandler errorHandler,
    const std::int32_t errorObject
  )
  {
    if (handle != nullptr) {
      if (handle->used != 0) {
        handle->errFunc = errorHandler;
        handle->errObj = errorObject;
      } else {
        SJUNI_CallErr_("E2004090266", kSofdecInvalidHandleSuffix);
      }
    } else {
      SJUNI_CallErr_("E2004090265", kSofdecNullPointerSuffix);
    }
  }

  /**
   * Address: 0x00B09C50 (FUN_00B09C50, _SJUNI_Reset)
   */
  void SJUNI_Reset(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    sjuni_Reset(handle);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09C70 (FUN_00B09C70, _sjuni_Reset)
   */
  void sjuni_Reset(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090267", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090268", kSofdecInvalidHandleSuffix);
      return;
    }

    std::int32_t nodeIndex = 0;
    moho::SofdecSjUnifyChunkNode* const chainPoolBase = handle->chainPoolBase;
    const std::int32_t nodeCountMinusOne = handle->chainPoolCount - 1;
    handle->chainPoolFreeList = chainPoolBase;

    const std::uintptr_t chainPoolBaseAddress = reinterpret_cast<std::uintptr_t>(chainPoolBase);
    if (nodeCountMinusOne > 0) {
      do {
        auto* const currentNode = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(
          chainPoolBaseAddress
          + (static_cast<std::uintptr_t>(nodeIndex) * sizeof(moho::SofdecSjUnifyChunkNode))
        );
        auto* const nextNode = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(
          chainPoolBaseAddress
          + (static_cast<std::uintptr_t>(nodeIndex + 1) * sizeof(moho::SofdecSjUnifyChunkNode))
        );
        currentNode->bufferAddress = 0;
        currentNode->next = nextNode;
        currentNode->byteCount = 0;
        ++nodeIndex;
      } while (nodeIndex < (handle->chainPoolCount - 1));
    }

    auto* const lastNode = reinterpret_cast<moho::SofdecSjUnifyChunkNode*>(
      chainPoolBaseAddress + (static_cast<std::uintptr_t>(nodeIndex) * sizeof(moho::SofdecSjUnifyChunkNode))
    );
    lastNode->next = nullptr;
    lastNode->bufferAddress = 0;
    lastNode->byteCount = 0;

    handle->laneHeads[0] = nullptr;
    handle->laneHeads[1] = nullptr;
    handle->laneHeads[2] = nullptr;
    handle->laneHeads[3] = nullptr;
  }

  /**
   * Address: 0x00B09D00 (FUN_00B09D00, _SJUNI_GetNumData)
   */
  std::int32_t SJUNI_GetNumData(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t readableBytes = sjuni_GetNumData(handle, lane);
    SJCRS_Unlock();
    return readableBytes;
  }

  /**
   * Address: 0x00B09D30 (FUN_00B09D30, _sjuni_GetNumData)
   */
  std::int32_t sjuni_GetNumData(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090269", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090270", kSofdecInvalidHandleSuffix);
      return 0;
    }

    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return 0;
    }

    std::int32_t totalBytes = 0;
    moho::SofdecSjUnifyChunkNode* chunkNode = handle->laneHeads[lane];
    while (chunkNode != nullptr) {
      totalBytes += chunkNode->byteCount;
      chunkNode = chunkNode->next;
    }
    return totalBytes;
  }

  /**
   * Address: 0x00B09DB0 (FUN_00B09DB0, _SJUNI_GetChunk)
   */
  void SJUNI_GetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    SJCRS_Lock();
    sjuni_GetChunk(handle, lane, requestedBytes, outChunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09DE0 (FUN_00B09DE0, _sjuni_GetChunk)
   */
  void sjuni_GetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    moho::SjChunkRange* const outChunkRange
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090271", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090272", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane >= 0 && lane < 4) {
      moho::SofdecSjUnifyChunkNode* const headNode = handle->laneHeads[lane];
      if (headNode != nullptr) {
        moho::SjChunkRange headChunk{};
        headChunk.bufferAddress = headNode->bufferAddress;
        headChunk.byteCount = headNode->byteCount;

        if (headChunk.byteCount <= requestedBytes) {
          outChunkRange->bufferAddress = headChunk.bufferAddress;
          outChunkRange->byteCount = headChunk.byteCount;
          handle->laneHeads[lane] = headNode->next;
          headNode->next = handle->chainPoolFreeList;
          handle->chainPoolFreeList = headNode;
          return;
        }

        if (handle->mergeAdjacentChunks == 1) {
          moho::SjChunkRange tailChunk{};
          SJ_SplitChunk(&headChunk, requestedBytes, &headChunk, &tailChunk);
          outChunkRange->bufferAddress = headChunk.bufferAddress;
          outChunkRange->byteCount = headChunk.byteCount;
          headNode->bufferAddress = tailChunk.bufferAddress;
          headNode->byteCount = tailChunk.byteCount;
          return;
        }
      }
    } else {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
    }

    outChunkRange->bufferAddress = 0;
    outChunkRange->byteCount = 0;
  }

  /**
   * Address: 0x00B09EF0 (FUN_00B09EF0, _SJUNI_PutChunk)
   */
  void SJUNI_PutChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjuni_PutChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B09F20 (FUN_00B09F20, _sjuni_PutChunk)
   */
  void sjuni_PutChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090273", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090274", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    const std::int32_t chunkAddress = chunkRange->bufferAddress;
    if (chunkAddress == 0) {
      return;
    }

    moho::SofdecSjUnifyChunkNode** tailLink = &handle->laneHeads[lane];
    moho::SofdecSjUnifyChunkNode* tailNode = nullptr;
    for (moho::SofdecSjUnifyChunkNode* node = *tailLink; node != nullptr; node = node->next) {
      tailLink = &node->next;
      tailNode = node;
    }

    if (handle->mergeAdjacentChunks == 1 && tailNode != nullptr) {
      const std::int32_t tailEndAddress = tailNode->bufferAddress + tailNode->byteCount;
      if (tailEndAddress == chunkAddress) {
        tailNode->byteCount += chunkBytes;
        return;
      }
    }

    moho::SofdecSjUnifyChunkNode* const freeNode = handle->chainPoolFreeList;
    if (freeNode == nullptr) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    handle->chainPoolFreeList = freeNode->next;
    freeNode->next = nullptr;
    freeNode->bufferAddress = chunkAddress;
    freeNode->byteCount = chunkBytes;
    *tailLink = freeNode;
  }

  /**
   * Address: 0x00B0A020 (FUN_00B0A020, _SJUNI_UngetChunk)
   */
  void SJUNI_UngetChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    SJCRS_Lock();
    sjuni_UngetChunk(handle, lane, chunkRange);
    SJCRS_Unlock();
  }

  /**
   * Address: 0x00B0A050 (FUN_00B0A050, _sjuni_UngetChunk)
   */
  void sjuni_UngetChunk(
    moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane, moho::SjChunkRange* const chunkRange
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090275", kSofdecNullPointerSuffix);
      return;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090276", kSofdecInvalidHandleSuffix);
      return;
    }

    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    const std::int32_t chunkBytes = chunkRange->byteCount;
    if (chunkBytes <= 0) {
      return;
    }

    const std::int32_t chunkAddress = chunkRange->bufferAddress;
    if (chunkAddress == 0) {
      return;
    }

    moho::SofdecSjUnifyChunkNode* const laneHead = handle->laneHeads[lane];
    if (handle->mergeAdjacentChunks == 1 && laneHead != nullptr) {
      if ((chunkAddress + chunkBytes) == laneHead->bufferAddress) {
        laneHead->bufferAddress = chunkAddress;
        laneHead->byteCount += chunkBytes;
        return;
      }
    }

    moho::SofdecSjUnifyChunkNode* const freeNode = handle->chainPoolFreeList;
    if (freeNode == nullptr) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return;
    }

    handle->chainPoolFreeList = freeNode->next;
    freeNode->next = handle->laneHeads[lane];
    freeNode->bufferAddress = chunkAddress;
    freeNode->byteCount = chunkBytes;
    handle->laneHeads[lane] = freeNode;
  }

  /**
   * Address: 0x00B0A140 (FUN_00B0A140, _SJUNI_IsGetChunk)
   */
  std::int32_t SJUNI_IsGetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    SJCRS_Lock();
    const std::int32_t available = sjuni_IsGetChunk(handle, lane, requestedBytes, outGrantedBytes);
    SJCRS_Unlock();
    return available;
  }

  /**
   * Address: 0x00B0A170 (FUN_00B0A170, _sjuni_IsGetChunk)
   */
  std::int32_t sjuni_IsGetChunk(
    moho::SofdecSjUnifyHandle* const handle,
    const std::int32_t lane,
    const std::int32_t requestedBytes,
    std::int32_t* const outGrantedBytes
  )
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090277", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090278", kSofdecInvalidHandleSuffix);
      return 0;
    }

    *outGrantedBytes = 0;
    if (lane < 0 || lane >= 4) {
      if (handle->errFunc != nullptr) {
        handle->errFunc(handle->errObj, -3);
      }
      return 0;
    }

    moho::SofdecSjUnifyChunkNode* const headNode = handle->laneHeads[lane];
    if (headNode == nullptr) {
      return 0;
    }

    *outGrantedBytes = headNode->byteCount;
    if (handle->mergeAdjacentChunks == 1) {
      return (headNode->byteCount >= requestedBytes) ? 1 : 0;
    }
    return (headNode->byteCount == requestedBytes) ? 1 : 0;
  }

  /**
   * Address: 0x00B0A230 (FUN_00B0A230, _SJUNI_GetNumChunk)
   */
  std::int32_t SJUNI_GetNumChunk(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    SJCRS_Lock();
    const std::int32_t chunkCount = sjuni_GetNumChunk(handle, lane);
    SJCRS_Unlock();
    return chunkCount;
  }

  /**
   * Address: 0x00B0A260 (FUN_00B0A260, _sjuni_GetNumChunk)
   */
  std::int32_t sjuni_GetNumChunk(moho::SofdecSjUnifyHandle* const handle, const std::int32_t lane)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090279", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090280", kSofdecInvalidHandleSuffix);
      return 0;
    }

    const std::intptr_t laneSlotAddress = reinterpret_cast<std::intptr_t>(&handle->laneHeads[0])
      + (static_cast<std::intptr_t>(lane) * static_cast<std::intptr_t>(sizeof(handle->laneHeads[0])));
    auto* const laneHeadSlot = reinterpret_cast<moho::SofdecSjUnifyChunkNode* const*>(laneSlotAddress);

    std::int32_t chunkCount = 0;
    for (moho::SofdecSjUnifyChunkNode* chunkNode = *laneHeadSlot; chunkNode != nullptr; chunkNode = chunkNode->next) {
      ++chunkCount;
    }
    return chunkCount;
  }

  /**
   * Address: 0x00B0A2B0 (FUN_00B0A2B0, _SJUNI_GetNumChainPool)
   */
  std::int32_t SJUNI_GetNumChainPool(moho::SofdecSjUnifyHandle* const handle)
  {
    SJCRS_Lock();
    const std::int32_t chainNodeCount = sjuni_GetNumChainPool(handle);
    SJCRS_Unlock();
    return chainNodeCount;
  }

  /**
   * Address: 0x00B0A2D0 (FUN_00B0A2D0, _sjuni_GetNumChainPool)
   */
  std::int32_t sjuni_GetNumChainPool(moho::SofdecSjUnifyHandle* const handle)
  {
    if (handle == nullptr) {
      SJUNI_CallErr_("E2004090281", kSofdecNullPointerSuffix);
      return 0;
    }
    if (handle->used == 0) {
      SJUNI_CallErr_("E2004090282", kSofdecInvalidHandleSuffix);
      return 0;
    }

    std::int32_t chainNodeCount = 0;
    for (
      moho::SofdecSjUnifyChunkNode* chainNode = handle->chainPoolFreeList;
      chainNode != nullptr;
      chainNode = chainNode->next
    ) {
      ++chainNodeCount;
    }
    return chainNodeCount;
  }

  /**
   * Address: 0x00B07B80 (FUN_00B07B80, _adxpc_err_dvd)
   *
   * What it does:
   * Forwards one DVD/file-system error-text lane to ADX error reporter.
   */
  std::int32_t ADXPC_ReportDvdError(const std::int32_t errorCode, char* const errorText)
  {
    (void)errorCode;
    return ADXERR_CallErrFunc1_(errorText);
  }

  constexpr std::uint16_t kAdxpcLibraryStringCrc = 0xE6FCu;
  constexpr std::int32_t kAdxpcDisplayHeightSystemMetricIndex = 1;
  constexpr std::int32_t kAdxpcFrameStatusRecoverableError = static_cast<std::int32_t>(0x88760219u);
  constexpr char kAdxpcExtendedLibraryRequiredErrorA[] = "E2004090901 : The extended library is required.";
  constexpr char kAdxpcExtendedLibraryRequiredErrorB[] = "E2004090902 : The extended library is required.";
  constexpr char kAdxpcLibraryValidationString[] = " CRI Middleware Library Professional Edition. ";
  constexpr char kAdxpcBuildVersionString[] = "\nADXPC(PRO) Ver.1.23 Build:Feb 28 2005 21:29:10\n";

  struct AdxpcVideoStatusPacketMode1
  {
    std::int32_t bufferBytes = 0; // +0x00
    std::int32_t statusFlags = 0; // +0x04
    std::array<std::int32_t, 93> reservedWords{}; // +0x08
  };

  static_assert(
    offsetof(AdxpcVideoStatusPacketMode1, bufferBytes) == 0x00,
    "AdxpcVideoStatusPacketMode1::bufferBytes offset must be 0x00"
  );
  static_assert(
    offsetof(AdxpcVideoStatusPacketMode1, statusFlags) == 0x04,
    "AdxpcVideoStatusPacketMode1::statusFlags offset must be 0x04"
  );
  static_assert(sizeof(AdxpcVideoStatusPacketMode1) == 0x17C, "AdxpcVideoStatusPacketMode1 size must be 0x17C");

  struct AdxpcVideoStatusPacketMode2
  {
    std::array<std::int32_t, 2> reservedWords0{}; // +0x00
    std::int32_t statusFlags = 0; // +0x08
    std::array<std::int32_t, 50> reservedWords1{}; // +0x0C
  };

  static_assert(
    offsetof(AdxpcVideoStatusPacketMode2, statusFlags) == 0x08,
    "AdxpcVideoStatusPacketMode2::statusFlags offset must be 0x08"
  );
  static_assert(sizeof(AdxpcVideoStatusPacketMode2) == 0xD4, "AdxpcVideoStatusPacketMode2 size must be 0xD4");

  using AdxpcQueryMode2StatusFn = std::int32_t(__stdcall*)(void* videoObject, AdxpcVideoStatusPacketMode2* outPacket);
  using AdxpcQueryMode1StatusFn = std::int32_t(__stdcall*)(void* videoObject, AdxpcVideoStatusPacketMode1* outPacket);
  using AdxpcQueryFrameStatusFn = std::int32_t(__stdcall*)(void* videoObject, std::int32_t* outValue);
  using AdxpcQueryFrameStatusPairFn = void(__stdcall*)(void* videoObject, std::int32_t outPair[2]);

  struct AdxpcVideoDispatchTable
  {
    void* reserved00[7]{}; // +0x00
    AdxpcQueryMode2StatusFn queryMode2Status = nullptr; // +0x1C
    void* reserved20[3]{}; // +0x20
    AdxpcQueryMode1StatusFn queryMode1Status = nullptr; // +0x2C
    void* reserved30[4]{}; // +0x30
    AdxpcQueryFrameStatusFn queryFrameStatus = nullptr; // +0x40
    AdxpcQueryFrameStatusPairFn queryFrameStatusPair = nullptr; // +0x44
  };

  static_assert(
    offsetof(AdxpcVideoDispatchTable, queryMode2Status) == 0x1C,
    "AdxpcVideoDispatchTable::queryMode2Status offset must be 0x1C"
  );
  static_assert(
    offsetof(AdxpcVideoDispatchTable, queryMode1Status) == 0x2C,
    "AdxpcVideoDispatchTable::queryMode1Status offset must be 0x2C"
  );
  static_assert(
    offsetof(AdxpcVideoDispatchTable, queryFrameStatus) == 0x40,
    "AdxpcVideoDispatchTable::queryFrameStatus offset must be 0x40"
  );
  static_assert(
    offsetof(AdxpcVideoDispatchTable, queryFrameStatusPair) == 0x44,
    "AdxpcVideoDispatchTable::queryFrameStatusPair offset must be 0x44"
  );
  static_assert(sizeof(AdxpcVideoDispatchTable) == 0x48, "AdxpcVideoDispatchTable size must be 0x48");

  struct AdxpcVideoObject
  {
    AdxpcVideoDispatchTable* dispatchTable = nullptr; // +0x00
  };

  struct AdxpcNestedValueLeaf
  {
    std::uint8_t mUnknown00[0x8]{}; // +0x00
    std::int32_t payloadWord = 0; // +0x08
  };

  static_assert(
    offsetof(AdxpcNestedValueLeaf, payloadWord) == 0x08,
    "AdxpcNestedValueLeaf::payloadWord offset must be 0x08"
  );
  static_assert(sizeof(AdxpcNestedValueLeaf) == 0x0C, "AdxpcNestedValueLeaf size must be 0x0C");

  struct AdxpcNestedValueParent
  {
    std::uint8_t mUnknown00[0x38]{}; // +0x00
    AdxpcNestedValueLeaf* leaf = nullptr; // +0x38
  };

  static_assert(
    offsetof(AdxpcNestedValueParent, leaf) == 0x38,
    "AdxpcNestedValueParent::leaf offset must be 0x38"
  );
  static_assert(sizeof(AdxpcNestedValueParent) == 0x3C, "AdxpcNestedValueParent size must be 0x3C");

  struct AdxpcNestedValueOwner
  {
    std::uint8_t mUnknown00[0x0C]{}; // +0x00
    AdxpcNestedValueParent* parent = nullptr; // +0x0C
  };

  static_assert(
    offsetof(AdxpcNestedValueOwner, parent) == 0x0C,
    "AdxpcNestedValueOwner::parent offset must be 0x0C"
  );
  static_assert(sizeof(AdxpcNestedValueOwner) == 0x10, "AdxpcNestedValueOwner size must be 0x10");

  const char* gAdxpcLibraryValidationPtr = kAdxpcLibraryValidationString;
  const char* gAdxpcBuildVersionPtr = kAdxpcBuildVersionString;
  std::int32_t gAdxpcVsyncInitCount = 0;
  AdxpcVideoObject* gAdxpcVideoObject = nullptr;
  std::int32_t gAdxpcVideoMode = 0;
  std::int32_t gAdxpcVideoProcessingSignal = 0;
  std::int32_t gAdxpcDisplayHeight = 0;
  std::int32_t gAdxmSelectedFrameworkMode = 0;
  std::int32_t gAdxmFramework = 0;
  std::int32_t gAdxmInitLevel = 0;

  std::int32_t ADXM_SetInterval2Thunk(std::int32_t interval);

  [[noreturn]] void adxpc_TrapForever()
  {
    while (true) {
    }
  }

  /**
   * Address: 0x00B14410 (FUN_00B14410, func_SofdecWaitForSignal)
   *
   * What it does:
   * Repeatedly tests-and-sets one signal lane for up to 1000 retries.
   */
  std::int32_t __cdecl SofdecWaitForSignal(std::int32_t signalLaneValue)
  {
    std::int32_t retries = 0;
    while (SVM_TestAndSet(&signalLaneValue) != TRUE) {
      Sleep(1u);
      if (++retries >= 1000) {
        return 0;
      }
    }
    return 1;
  }

  /**
   * Address: 0x00B14450 (FUN_00B14450, nullsub_3623)
   *
   * What it does:
   * Legacy no-op signal-release callback.
   */
  void __cdecl SofdecSignalReleaseLegacyNoOp(const std::int32_t signalLaneValue)
  {
    (void)signalLaneValue;
  }

  /**
   * Address: 0x00B14090 (FUN_00B14090, _adxpc_calcCrc)
   *
   * What it does:
   * Computes the ADXPC 16-bit CRC over one byte buffer.
   */
  std::int32_t __cdecl adxpc_CalculateCrc16(const char* const byteBuffer, const std::int32_t byteCount)
  {
    std::uint16_t crc = 0;
    for (std::int32_t index = 0; index < byteCount; ++index) {
      crc ^= static_cast<std::uint16_t>(static_cast<std::uint8_t>(byteBuffer[index]) << 8u);
      for (std::int32_t bit = 0; bit < 8; ++bit) {
        if ((crc & 0x8000u) != 0u) {
          crc = static_cast<std::uint16_t>((crc << 1u) ^ 0x1021u);
        } else {
          crc = static_cast<std::uint16_t>(crc << 1u);
        }
      }
    }
    return static_cast<std::int32_t>(crc);
  }

  /**
   * Address: 0x00B14020 (FUN_00B14020, _adxpc_checkLibStr)
   *
   * What it does:
   * Validates the ADXPC embedded library string and traps forever on mismatch.
   */
  std::int32_t __cdecl adxpc_ValidateLibrarySignature(char* const libraryString)
  {
    std::int8_t maxChar = static_cast<std::int8_t>(libraryString[0]);
    std::int8_t minChar = static_cast<std::int8_t>(libraryString[0]);
    const std::int32_t textLength = ::lstrlenA(libraryString);
    if (textLength < 3) {
      adxpc_TrapForever();
    }

    for (std::int32_t index = 0; index < textLength; ++index) {
      const std::int8_t currentChar = static_cast<std::int8_t>(libraryString[index]);
      if (currentChar <= 0) {
        adxpc_TrapForever();
      }

      if (maxChar < currentChar) {
        maxChar = currentChar;
      } else if (minChar > currentChar) {
        minChar = currentChar;
      }
    }

    if (maxChar == minChar) {
      adxpc_TrapForever();
    }

    const std::int32_t crc = adxpc_CalculateCrc16(libraryString, textLength);
    if (static_cast<std::uint16_t>(crc) != kAdxpcLibraryStringCrc) {
      adxpc_TrapForever();
    }
    return crc;
  }

  /**
   * Address: 0x00B13CD0 (FUN_00B13CD0, _ADXPC_ExecServer)
   *
   * What it does:
   * Thunk alias that forwards to `ADXT_ExecServer`.
   */
  void ADXPC_ExecServer()
  {
    ADXT_ExecServer();
  }

  /**
   * Address: 0x00B13CE0 (FUN_00B13CE0, _ADXPC_ExecServerEx)
   *
   * What it does:
   * Executes one ADXT server tick with reentry guard and returns zero.
   */
  std::int32_t ADXPC_ExecServerEx()
  {
    static std::int32_t sAdxpcExecServerGuard = 0;
    if (sAdxpcExecServerGuard == 0) {
      sAdxpcExecServerGuard = 1;
      ADXT_ExecServer();
      sAdxpcExecServerGuard = 0;
    }
    return 0;
  }

  /**
   * Address: 0x00B13FE0 (FUN_00B13FE0, _ADXPC_GetVersion)
   *
   * What it does:
   * Validates ADXPC middleware signature text and returns build version text.
   */
  char* ADXPC_GetVersion()
  {
    (void)adxpc_ValidateLibrarySignature(const_cast<char*>(gAdxpcLibraryValidationPtr));
    return const_cast<char*>(gAdxpcBuildVersionPtr);
  }

  /**
   * Address: 0x00B14000 (FUN_00B14000, sub_B14000)
   *
   * What it does:
   * Returns nested payload lane (`+0x0C -> +0x38 -> +0x08`) when present.
   */
  [[maybe_unused]] std::int32_t adxpc_GetNestedPayloadWord(const AdxpcNestedValueOwner* const owner)
  {
    AdxpcNestedValueParent* const parent = owner->parent;
    if (parent == nullptr) {
      return 0;
    }

    AdxpcNestedValueLeaf* const leaf = parent->leaf;
    if (leaf == nullptr) {
      return 0;
    }
    return leaf->payloadWord;
  }

  /**
   * Address: 0x00B140D0 (FUN_00B140D0, func_SofdecFunc1a)
   *
   * What it does:
   * Polls ADXPC video object status and returns whether the ready bit is set.
   */
  [[maybe_unused]] std::int32_t SofdecIsVideoProcessingReady()
  {
    if (SofdecWaitForSignal(gAdxpcVideoProcessingSignal) == 0) {
      return 0;
    }

    std::int32_t ready = 0;
    if (gAdxpcVideoObject != nullptr && gAdxpcVideoMode > 0) {
      std::int32_t statusFlags = 0;
      if (gAdxpcVideoMode == 1) {
        AdxpcVideoStatusPacketMode1 statusPacket{};
        statusPacket.bufferBytes = static_cast<std::int32_t>(sizeof(AdxpcVideoStatusPacketMode1));
        if (gAdxpcVideoObject->dispatchTable->queryMode1Status(gAdxpcVideoObject, &statusPacket) >= 0) {
          statusFlags = statusPacket.statusFlags;
        }
      } else if (gAdxpcVideoMode == 2) {
        AdxpcVideoStatusPacketMode2 statusPacket{};
        if (gAdxpcVideoObject->dispatchTable->queryMode2Status(gAdxpcVideoObject, &statusPacket) >= 0) {
          statusFlags = statusPacket.statusFlags;
        }
      }

      if ((statusFlags & 0x20000) != 0) {
        ready = 1;
      }
    }

    SofdecSignalReleaseLegacyNoOp(gAdxpcVideoProcessingSignal);
    return ready;
  }

  /**
   * Address: 0x00B14190 (FUN_00B14190, func_SofDecFunc1)
   *
   * What it does:
   * Reads one ADXPC video frame-status lane for the active mode.
   */
  std::int32_t SofdecQueryVideoFrameStatus()
  {
    std::int32_t frameStatus = 0;
    const std::int32_t acquired = SofdecWaitForSignal(gAdxpcVideoProcessingSignal);
    if (acquired == 0) {
      return 0;
    }

    if (gAdxpcVideoObject != nullptr && gAdxpcVideoMode > 0) {
      if (gAdxpcVideoMode == 1) {
        const std::int32_t queryResult
          = gAdxpcVideoObject->dispatchTable->queryFrameStatus(gAdxpcVideoObject, &frameStatus);
        if (queryResult < 0) {
          frameStatus = (queryResult != kAdxpcFrameStatusRecoverableError) ? -1 : 0;
        }
      } else if (gAdxpcVideoMode == 2) {
        std::int32_t statusPair[2]{};
        gAdxpcVideoObject->dispatchTable->queryFrameStatusPair(gAdxpcVideoObject, statusPair);
        frameStatus = (statusPair[0] != 0) ? -1 : statusPair[1];
      } else {
        frameStatus = 0;
      }
    }

    SofdecSignalReleaseLegacyNoOp(gAdxpcVideoProcessingSignal);
    return frameStatus;
  }

  std::uint32_t __cdecl SofdecQueryVideoFrameStatusCallback()
  {
    return static_cast<std::uint32_t>(SofdecQueryVideoFrameStatus());
  }

  /**
   * Address: 0x00B14240 (FUN_00B14240, sub_B14240)
   *
   * What it does:
   * Measures stable ADXPC refresh interval from scanline transitions.
   */
  std::int32_t SofdecMeasureVideoRefreshRate()
  {
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);

    std::array<std::int32_t, 2> samples{};
    for (std::int32_t outerAttempt = 0; outerAttempt < 10; ++outerAttempt) {
      for (std::int32_t sampleIndex = 0; sampleIndex < 2; ++sampleIndex) {
        LARGE_INTEGER startCounter{};
        QueryPerformanceCounter(&startCounter);

        std::uint32_t baselineScanline = 0;
        while (true) {
          LARGE_INTEGER probeCounter{};
          QueryPerformanceCounter(&probeCounter);
          if (AdxmElapsedMicroseconds(startCounter, probeCounter, frequency.QuadPart) > 100000) {
            return 0;
          }

          baselineScanline = static_cast<std::uint32_t>(SofdecQueryVideoFrameStatus());
          if (baselineScanline >= 0x32u && baselineScanline <= 0x64u) {
            break;
          }
        }

        std::int32_t hasWrappedPastBottom = 0;
        QueryPerformanceCounter(&startCounter);
        while (true) {
          const std::uint32_t currentScanline = static_cast<std::uint32_t>(SofdecQueryVideoFrameStatus());
          LARGE_INTEGER nowCounter{};
          QueryPerformanceCounter(&nowCounter);
          if (AdxmElapsedMicroseconds(startCounter, nowCounter, frequency.QuadPart) > 100000) {
            break;
          }

          if (currentScanline > static_cast<std::uint32_t>(gAdxpcDisplayHeight)) {
            hasWrappedPastBottom = 1;
          } else if (hasWrappedPastBottom != 1) {
            continue;
          }

          if (
            currentScanline > baselineScanline + 10u
            && currentScanline <= static_cast<std::uint32_t>(gAdxpcDisplayHeight)
          ) {
            break;
          }

          if (currentScanline >= baselineScanline && currentScanline <= baselineScanline + 10u) {
            const auto elapsedMicroseconds
              = static_cast<std::uint32_t>(AdxmElapsedMicroseconds(startCounter, nowCounter, frequency.QuadPart));
            samples[static_cast<std::size_t>(sampleIndex)] = static_cast<std::int32_t>(100000000u / elapsedMicroseconds);
            goto sample_done;
          }
        }

        samples[static_cast<std::size_t>(sampleIndex)] = 0;
      sample_done:
        continue;
      }

      if (
        samples[0] != 0 && samples[0] <= samples[1] + 10
        && samples[0] >= samples[1] - 10
      ) {
        return (samples[0] + samples[1]) / 2;
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B13D20 (FUN_00B13D20, sub_B13D20)
   *
   * What it does:
   * Legacy helper that updates only the XECI read-mode lane.
   */
  void xeci_set_read_mode_simple(const std::int32_t readMode)
  {
    xeci_set_read_mode(0, 0, 0, readMode);
  }

  /**
   * Address: 0x00B13D40 (FUN_00B13D40, sub_B13D40)
   *
   * What it does:
   * Returns the incoming owner pointer value, and when output is provided
   * resolves and writes one nested payload word.
   */
  std::int32_t adxpc_QueryNestedPayloadWordAndStore(
    AdxpcNestedValueOwner* const owner,
    std::int32_t* const outPayloadWord
  )
  {
    std::int32_t result = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(owner));
    if (owner != nullptr && outPayloadWord != nullptr) {
      result = adxpc_GetNestedPayloadWord(owner);
      *outPayloadWord = result;
    }
    return result;
  }

  /**
   * Address: 0x00B13D60 (FUN_00B13D60, sub_B13D60)
   *
   * What it does:
   * Compatibility thunk that forwards to global Sofdec buffer-placement setter.
   */
  std::int32_t SofdecSetBufferPlacementModeDispatch(const std::int32_t bufferPlacementMode)
  {
    return SofdecSetBufferPlacementMode(bufferPlacementMode);
  }

  /**
   * Address: 0x00B13D70 (FUN_00B13D70, sub_B13D70)
   *
   * What it does:
   * Compatibility thunk that forwards to global Sofdec buffer-placement getter.
   */
  std::int32_t SofdecGetBufferPlacementModeDispatch()
  {
    return SofdecGetBufferPlacementMode();
  }

  /**
   * Address: 0x00B13D80 (FUN_00B13D80, sub_B13D80)
   *
   * What it does:
   * Compatibility thunk that forwards to global Sofdec mono-routing setter.
   */
  std::int32_t SofdecSetMonoRoutingModeDispatch(const std::int32_t monoRoutingMode)
  {
    return SofdecSetMonoRoutingMode(monoRoutingMode);
  }

  /**
   * Address: 0x00B13D90 (FUN_00B13D90, sub_B13D90)
   *
   * What it does:
   * Compatibility thunk that forwards to global Sofdec mono-routing getter.
   */
  std::int32_t SofdecGetMonoRoutingModeDispatch()
  {
    return SofdecGetMonoRoutingMode();
  }

  /**
   * Address: 0x00B13DA0 (FUN_00B13DA0, sub_B13DA0)
   *
   * What it does:
   * Thin thunk wrapper for nested ADXPC payload query helper.
   */
  std::int32_t adxpc_QueryNestedPayloadWordAndStoreThunk(
    AdxpcNestedValueOwner* const owner,
    std::int32_t* const outPayloadWord
  )
  {
    return adxpc_QueryNestedPayloadWordAndStore(owner, outPayloadWord);
  }

  /**
   * Address: 0x00B13DB0 (FUN_00B13DB0, sub_B13DB0)
   *
   * What it does:
   * Thin thunk wrapper for Sofdec mono-routing mode setter dispatch.
   */
  std::int32_t SofdecSetMonoRoutingModeDispatchThunk(const std::int32_t monoRoutingMode)
  {
    return SofdecSetMonoRoutingModeDispatch(monoRoutingMode);
  }

  /**
   * Address: 0x00B13DC0 (FUN_00B13DC0, sub_B13DC0)
   *
   * What it does:
   * Thin thunk wrapper for Sofdec mono-routing mode getter dispatch.
   */
  std::int32_t SofdecGetMonoRoutingModeDispatchThunk()
  {
    return SofdecGetMonoRoutingModeDispatch();
  }

  /**
   * Address: 0x00B13DD0 (FUN_00B13DD0, sub_B13DD0)
   *
   * What it does:
   * Thin thunk wrapper for Sofdec buffer-placement mode setter dispatch.
   */
  std::int32_t SofdecSetBufferPlacementModeDispatchThunk(const std::int32_t bufferPlacementMode)
  {
    return SofdecSetBufferPlacementModeDispatch(bufferPlacementMode);
  }

  /**
   * Address: 0x00B13DE0 (FUN_00B13DE0, sub_B13DE0)
   *
   * What it does:
   * Secondary compatibility thunk for Sofdec buffer-placement mode getter.
   */
  std::int32_t SofdecGetBufferPlacementModeDispatchThunk()
  {
    return SofdecGetBufferPlacementModeDispatch();
  }

  /**
   * Address: 0x00B13F00 (FUN_00B13F00, sub_B13F00)
   *
   * What it does:
   * Initializes ADXPC video-sync runtime lanes and timing callbacks.
   */
  std::int32_t ADXPC_InitializeVideoSyncRuntime()
  {
    if (gAdxpcVideoObject == nullptr || gAdxpcVideoMode <= 0) {
      return 0;
    }
    if (SofdecIsVideoProcessingReady() == 0) {
      return 0;
    }

    gAdxpcDisplayHeight = GetSystemMetrics(kAdxpcDisplayHeightSystemMetricIndex);
    (void)SofdecSetScreenHeight2(gAdxpcDisplayHeight);

    const std::int32_t refreshInterval = SofdecMeasureVideoRefreshRate();
    if (refreshInterval == 0) {
      return 0;
    }

    (void)ADXM_SetInterval1(refreshInterval);
    if (SofdecSetFrameReadCallback(&SofdecQueryVideoFrameStatusCallback) == 0) {
      return 0;
    }

    (void)ADXM_SetInterval2Thunk((100000 / refreshInterval) / 2);
    return refreshInterval;
  }

  /**
   * Address: 0x00B13E90 (FUN_00B13E90, sub_B13E90)
   *
   * What it does:
   * Releases one ADXPC video-sync user and tears down runtime lanes when last.
   */
  std::int32_t ADXPC_EndVideoSyncSession()
  {
    --gAdxpcVsyncInitCount;
    if (gAdxpcVsyncInitCount != 0) {
      return 1;
    }

    (void)ADXM_SetInterval2Thunk(0);
    std::int32_t result = SofdecSetFrameReadCallback(nullptr);
    if (result == 0) {
      return result;
    }

    (void)ADXM_SetInterval1(6000);
    result = SofdecWaitForSignal(gAdxpcVideoProcessingSignal);
    if (result == 0) {
      return result;
    }

    gAdxpcVideoMode = 0;
    gAdxpcVideoObject = nullptr;
    SofdecSignalReleaseLegacyNoOp(gAdxpcVideoProcessingSignal);
    return 1;
  }

  /**
   * Address: 0x00B13E10 (FUN_00B13E10, sub_B13E10)
   *
   * What it does:
   * Registers one ADXPC video object/mode and initializes vsync runtime once.
   */
  std::int32_t ADXPC_BeginVideoSyncSession(AdxpcVideoObject* const videoObject, const std::int32_t videoMode)
  {
    std::int32_t initResult = 0;
    if (videoObject == nullptr || videoMode <= 0) {
      return 0;
    }

    if (gAdxpcVsyncInitCount == 0) {
      if (SofdecWaitForSignal(gAdxpcVideoProcessingSignal) == 0) {
        return 0;
      }

      gAdxpcVideoMode = videoMode;
      gAdxpcVideoObject = videoObject;
      SofdecSignalReleaseLegacyNoOp(gAdxpcVideoProcessingSignal);

      initResult = ADXPC_InitializeVideoSyncRuntime();
      if (initResult == 0) {
        (void)ADXPC_EndVideoSyncSession();
      }
    }

    ++gAdxpcVsyncInitCount;
    return initResult;
  }

  /**
   * Address: 0x00B13DF0 (FUN_00B13DF0, sub_B13DF0)
   *
   * What it does:
   * Reports missing ADXPC extended library (error lane #1).
   */
  std::int32_t ADXPC_ReportExtendedLibraryRequiredErrorA()
  {
    ADXERR_CallErrFunc1_(kAdxpcExtendedLibraryRequiredErrorA);
    return 0;
  }

  /**
   * Address: 0x00B13E00 (FUN_00B13E00, sub_B13E00)
   *
   * What it does:
   * Reports missing ADXPC extended library (error lane #2).
   */
  void ADXPC_ReportExtendedLibraryRequiredErrorB()
  {
    ADXERR_CallErrFunc1_(kAdxpcExtendedLibraryRequiredErrorB);
  }

  /**
   * Address: 0x00B105D0 (FUN_00B105D0, _ADXMNG_SetFramework)
   *
   * What it does:
   * Publishes selected ADXM framework lane and returns the written mode.
   */
  std::int32_t ADXMNG_SetFramework(const std::int32_t frameworkMode)
  {
    gAdxmFramework = frameworkMode;
    return frameworkMode;
  }

  /**
   * Address: 0x00B144F0 (FUN_00B144F0, sub_B144F0)
   *
   * What it does:
   * Maps external ADXM framework selector mode into runtime framework lane.
   */
  std::int32_t ADXM_MapFrameworkMode(const std::int32_t selectedMode)
  {
    if (selectedMode == 1) {
      return 1;
    }
    return 2;
  }

  /**
   * Address: 0x00B14460 (FUN_00B14460, sub_B14460)
   *
   * What it does:
   * Selects ADXM framework mode, stores selected mode lane, and conditionally
   * starts ADXM thread runtime for startup-driven modes.
   */
  std::int32_t ADXM_SelectFrameworkMode(
    const std::int32_t selectedMode,
    const moho::AdxmThreadStartupParams* const startupParams
  )
  {
    (void)ADXMNG_SetFramework(ADXM_MapFrameworkMode(selectedMode));
    gAdxmSelectedFrameworkMode = selectedMode;

    if (selectedMode == 0 || selectedMode == 2) {
      ADXM_SetupThrd(startupParams);
      return 1;
    }
    if (selectedMode == 1) {
      return 1;
    }
    return 0;
  }

  /**
   * Address: 0x00B144B0 (FUN_00B144B0, sub_B144B0)
   *
   * What it does:
   * Finalizes active ADXM runtime modes and clears framework lane on exit.
   */
  std::int32_t ADXM_ShutdownSelectedFramework()
  {
    std::int32_t result = 1;
    if (gAdxmSelectedFrameworkMode == 0 || gAdxmSelectedFrameworkMode == 2) {
      ADXM_Finish();
    } else if (gAdxmSelectedFrameworkMode != 1) {
      result = 0;
    }

    (void)ADXMNG_SetFramework(-1);
    return result;
  }

  constexpr std::size_t kCvFsDeviceSlotCount = 32;
  constexpr std::size_t kCvFsHandlePoolCount = 80;
  constexpr std::size_t kCvFsDeviceNameBytes = 12;
  constexpr std::size_t kCvFsPathScratchBytes = 300;
  std::array<CvFsDeviceSlot, kCvFsDeviceSlotCount> gCvFsDeviceSlots{};
  std::array<CvFsHandleView, kCvFsHandlePoolCount> gCvFsHandlePool{};
  std::array<char, kCvFsDeviceNameBytes> gCvFsDefaultDeviceName{};
  std::array<char, kCvFsPathScratchBytes> gCvFsAddDevicePathScratch{};
  std::int32_t gCvFsErrorObject = 0;
  std::array<char, MAX_PATH> gXeDirRootDirectory{};

  /**
   * Address: 0x00B12000 (FUN_00B12000, _toUpperStr)
   *
   * What it does:
   * Uppercases one zero-terminated CVFS lane in place.
   */
  std::int32_t toUpperStr(char* const text)
  {
    if (text == nullptr) {
      return 0;
    }

    std::int32_t lastSymbol = 0;
    const std::size_t symbolCount = std::strlen(text) + 1u;
    for (std::size_t index = 0; index < symbolCount; ++index) {
      lastSymbol = static_cast<unsigned char>(text[index]);
      if (lastSymbol >= 'a' && lastSymbol <= 'z') {
        lastSymbol -= ('a' - 'A');
        text[index] = static_cast<char>(lastSymbol);
      }
    }
    return lastSymbol;
  }

  /**
   * Address: 0x00B12110 (FUN_00B12110, _isExistDev)
   *
   * What it does:
   * Returns whether one CVFS device-name prefix is registered.
   */
  std::int32_t isExistDev(const char* const deviceName, const std::size_t compareLength)
  {
    if (deviceName == nullptr) {
      return 0;
    }

    for (const CvFsDeviceSlot& deviceSlot : gCvFsDeviceSlots) {
      if (std::strncmp(deviceName, deviceSlot.deviceName.data(), compareLength) == 0) {
        return 1;
      }
    }
    return 0;
  }

  /**
   * Address: 0x00B10990 (FUN_00B10990, _xeDirAppendRootDir)
   *
   * What it does:
   * Appends one relative/absolute path onto the configured CVFS root lane.
   */
  char* __cdecl xeDirAppendRootDir(char* const outputPath, const char* const relativeOrAbsolutePath)
  {
    if (relativeOrAbsolutePath != nullptr) {
      if (relativeOrAbsolutePath[0] != '\0') {
        if (relativeOrAbsolutePath[0] == '\\') {
          outputPath[0] = gXeDirRootDirectory[0];
          outputPath[1] = gXeDirRootDirectory[1];
          outputPath[2] = '\0';
        } else if (relativeOrAbsolutePath[1] == ':') {
          outputPath[0] = '\0';
        } else {
          std::strcpy(outputPath, gXeDirRootDirectory.data());
        }
      } else {
        std::strcpy(outputPath, gXeDirRootDirectory.data());
      }

      std::strcat(outputPath, relativeOrAbsolutePath);
      return nullptr;
    }

    const char* readCursor = gXeDirRootDirectory.data();
    char copiedLane = '\0';
    do {
      copiedLane = *readCursor;
      outputPath[readCursor - gXeDirRootDirectory.data()] = copiedLane;
      ++readCursor;
    } while (copiedLane != '\0');
    return const_cast<char*>(readCursor);
  }

  /**
   * Address: 0x00B11A90 (FUN_00B11A90, _xeDirSetRootDir)
   *
   * What it does:
   * Stores one full CVFS root-directory path and guarantees a trailing
   * backslash separator.
   */
  std::int32_t xeDirSetRootDir(const char* const rootDirectory)
  {
    char fileName[MAX_PATH]{};
    if (rootDirectory != nullptr) {
      std::snprintf(fileName, sizeof(fileName), "%s", rootDirectory);
    }

    if (std::strlen(fileName) == 0u) {
      std::strcpy(fileName, ".");
    }

    std::memset(gXeDirRootDirectory.data(), 0, gXeDirRootDirectory.size());
    ::GetFullPathNameA(
      fileName,
      static_cast<DWORD>(gXeDirRootDirectory.size()),
      gXeDirRootDirectory.data(),
      nullptr
    );

    const std::size_t rootLength = std::strlen(gXeDirRootDirectory.data());
    if (rootLength == 0u || gXeDirRootDirectory[rootLength - 1u] != '\\') {
      if (rootLength + 1u < gXeDirRootDirectory.size()) {
        gXeDirRootDirectory[rootLength] = '\\';
        gXeDirRootDirectory[rootLength + 1u] = '\0';
      }
    }

    return 0;
  }

  /**
   * Address: 0x00B11B40 (FUN_00B11B40, _xeDirGetRootDir)
   *
   * What it does:
   * Returns the currently configured XEDIR root directory lane.
   */
  char* xeDirGetRootDir()
  {
    return gXeDirRootDirectory.data();
  }

  /**
   * Address: 0x00B11DE0 (FUN_00B11DE0, _cvFsError_)
   *
   * What it does:
   * Bridges one CVFS error text to the registered user error callback lane.
   */
