#pragma once

// Engine addition (issue #255): SAL annotations for DirectXMath and DirectXTex on Linux, where
// nothing checks them. Generated from the annotations those trees use
// (tmp/claude/linux-faf/gen_sal.py); each is defined empty.

#if FAFRE_PLATFORM_WINDOWS
#error "platform/posix/sal/sal.h is for builds without the Windows SDK"
#endif

#ifndef _COM_Outptr_
#define _COM_Outptr_
#endif
#ifndef _In_
#define _In_
#endif
#ifndef _In_opt_
#define _In_opt_
#endif
#ifndef _In_z_
#define _In_z_
#endif
#ifndef _Inout_
#define _Inout_
#endif
#ifndef _Inout_opt_
#define _Inout_opt_
#endif
#ifndef _Out_
#define _Out_
#endif
#ifndef _Out_opt_
#define _Out_opt_
#endif
#ifndef _Outptr_
#define _Outptr_
#endif
#ifndef _Reserved_
#define _Reserved_
#endif
#ifndef _Use_decl_annotations_
#define _Use_decl_annotations_
#endif
#ifndef _Analysis_assume_
#define _Analysis_assume_(...)
#endif
#ifndef _In_count_
#define _In_count_(...)
#endif
#ifndef _In_range_
#define _In_range_(...)
#endif
#ifndef _In_reads_
#define _In_reads_(...)
#endif
#ifndef _In_reads_bytes_
#define _In_reads_bytes_(...)
#endif
#ifndef _In_reads_opt_
#define _In_reads_opt_(...)
#endif
#ifndef _Inout_updates_all_
#define _Inout_updates_all_(...)
#endif
#ifndef _Inout_updates_all_opt_
#define _Inout_updates_all_opt_(...)
#endif
#ifndef _Inout_updates_bytes_
#define _Inout_updates_bytes_(...)
#endif
#ifndef _Out_writes_
#define _Out_writes_(...)
#endif
#ifndef _Out_writes_all_
#define _Out_writes_all_(...)
#endif
#ifndef _Out_writes_bytes_
#define _Out_writes_bytes_(...)
#endif
#ifndef _Out_writes_bytes_to_opt_
#define _Out_writes_bytes_to_opt_(...)
#endif
#ifndef _Out_writes_opt_
#define _Out_writes_opt_(...)
#endif
#ifndef _Success_
#define _Success_(...)
#endif
#ifndef _When_
#define _When_(...)
#endif
