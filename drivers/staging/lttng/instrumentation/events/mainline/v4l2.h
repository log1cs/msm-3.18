/* 2017-05-30: File added by Sony Corporation */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM v4l2

#if !defined(_TRACE_V4L2_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_V4L2_H

#include <linux/tracepoint.h>

#define show_type(type)							       \
	__print_symbolic(type,						       \
		{ V4L2_BUF_TYPE_VIDEO_CAPTURE,	      "VIDEO_CAPTURE" },       \
		{ V4L2_BUF_TYPE_VIDEO_OUTPUT,	      "VIDEO_OUTPUT" },	       \
		{ V4L2_BUF_TYPE_VIDEO_OVERLAY,	      "VIDEO_OVERLAY" },       \
		{ V4L2_BUF_TYPE_VBI_CAPTURE,	      "VBI_CAPTURE" },	       \
		{ V4L2_BUF_TYPE_VBI_OUTPUT,	      "VBI_OUTPUT" },	       \
		{ V4L2_BUF_TYPE_SLICED_VBI_CAPTURE,   "SLICED_VBI_CAPTURE" },  \
		{ V4L2_BUF_TYPE_SLICED_VBI_OUTPUT,    "SLICED_VBI_OUTPUT" },   \
		{ V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY, "VIDEO_OUTPUT_OVERLAY" },\
		{ V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE, "VIDEO_CAPTURE_MPLANE" },\
		{ V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE,  "VIDEO_OUTPUT_MPLANE" }, \
		{ V4L2_BUF_TYPE_PRIVATE,	      "PRIVATE" })

#define show_field(field)						\
	__print_symbolic(field,						\
		{ V4L2_FIELD_ANY,		"ANY" },		\
		{ V4L2_FIELD_NONE,		"NONE" },		\
		{ V4L2_FIELD_TOP,		"TOP" },		\
		{ V4L2_FIELD_BOTTOM,		"BOTTOM" },		\
		{ V4L2_FIELD_INTERLACED,	"INTERLACED" },		\
		{ V4L2_FIELD_SEQ_TB,		"SEQ_TB" },		\
		{ V4L2_FIELD_SEQ_BT,		"SEQ_BT" },		\
		{ V4L2_FIELD_ALTERNATE,		"ALTERNATE" },		\
		{ V4L2_FIELD_INTERLACED_TB,	"INTERLACED_TB" },      \
		{ V4L2_FIELD_INTERLACED_BT,	"INTERLACED_BT" })

#define show_timecode_type(type)					\
	__print_symbolic(type,						\
		{ V4L2_TC_TYPE_24FPS,		"24FPS" },		\
		{ V4L2_TC_TYPE_25FPS,		"25FPS" },		\
		{ V4L2_TC_TYPE_30FPS,		"30FPS" },		\
		{ V4L2_TC_TYPE_50FPS,		"50FPS" },		\
		{ V4L2_TC_TYPE_60FPS,		"60FPS" })

#define show_flags(flags)						      \
	__print_flags(flags, "|",					      \
		{ V4L2_BUF_FLAG_MAPPED,		     "MAPPED" },	      \
		{ V4L2_BUF_FLAG_QUEUED,		     "QUEUED" },	      \
		{ V4L2_BUF_FLAG_DONE,		     "DONE" },		      \
		{ V4L2_BUF_FLAG_KEYFRAME,	     "KEYFRAME" },	      \
		{ V4L2_BUF_FLAG_PFRAME,		     "PFRAME" },	      \
		{ V4L2_BUF_FLAG_BFRAME,		     "BFRAME" },	      \
		{ V4L2_BUF_FLAG_ERROR,		     "ERROR" },		      \
		{ V4L2_BUF_FLAG_TIMECODE,	     "TIMECODE" },	      \
		{ V4L2_BUF_FLAG_PREPARED,	     "PREPARED" },	      \
		{ V4L2_BUF_FLAG_NO_CACHE_INVALIDATE, "NO_CACHE_INVALIDATE" }, \
		{ V4L2_BUF_FLAG_NO_CACHE_CLEAN,	     "NO_CACHE_CLEAN" },      \
		{ V4L2_BUF_FLAG_TIMESTAMP_MASK,	     "TIMESTAMP_MASK" },      \
		{ V4L2_BUF_FLAG_TIMESTAMP_UNKNOWN,   "TIMESTAMP_UNKNOWN" },   \
		{ V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC, "TIMESTAMP_MONOTONIC" }, \
		{ V4L2_BUF_FLAG_TIMESTAMP_COPY,	     "TIMESTAMP_COPY" })

#define show_timecode_flags(flags)					  \
	__print_flags(flags, "|",					  \
		{ V4L2_TC_FLAG_DROPFRAME,       "DROPFRAME" },		  \
		{ V4L2_TC_FLAG_COLORFRAME,      "COLORFRAME" },		  \
		{ V4L2_TC_USERBITS_USERDEFINED,	"USERBITS_USERDEFINED" }, \
		{ V4L2_TC_USERBITS_8BITCHARS,	"USERBITS_8BITCHARS" })

#define V4L2_TRACE_EVENT(event_name)					\
	TRACE_EVENT(event_name,						\
		TP_PROTO(int minor, struct v4l2_buffer *buf),		\
									\
		TP_ARGS(minor, buf),					\
									\
		TP_STRUCT__entry(					\
			__field(int, minor)				\
			__field(u32, index)				\
			__field(u32, type)				\
			__field(u32, bytesused)				\
			__field(u32, flags)				\
			__field(u32, field)				\
			__field(s64, timestamp)				\
			__field(u32, timecode_type)			\
			__field(u32, timecode_flags)			\
			__field(u8, timecode_frames)			\
			__field(u8, timecode_seconds)			\
			__field(u8, timecode_minutes)			\
			__field(u8, timecode_hours)			\
			__field(u8, timecode_userbits0)			\
			__field(u8, timecode_userbits1)			\
			__field(u8, timecode_userbits2)			\
			__field(u8, timecode_userbits3)			\
			__field(u32, sequence)				\
		),							\
									\
		TP_fast_assign(						\
			__entry->minor = minor;				\
			__entry->index = buf->index;			\
			__entry->type = buf->type;			\
			__entry->bytesused = buf->bytesused;		\
			__entry->flags = buf->flags;			\
			__entry->field = buf->field;			\
			__entry->timestamp =				\
				timeval_to_ns(&buf->timestamp);		\
			__entry->timecode_type = buf->timecode.type;	\
			__entry->timecode_flags = buf->timecode.flags;	\
			__entry->timecode_frames =			\
				buf->timecode.frames;			\
			__entry->timecode_seconds =			\
				buf->timecode.seconds;			\
			__entry->timecode_minutes =			\
				buf->timecode.minutes;			\
			__entry->timecode_hours = buf->timecode.hours;	\
			__entry->timecode_userbits0 =			\
				buf->timecode.userbits[0];		\
			__entry->timecode_userbits1 =			\
				buf->timecode.userbits[1];		\
			__entry->timecode_userbits2 =			\
				buf->timecode.userbits[2];		\
			__entry->timecode_userbits3 =			\
				buf->timecode.userbits[3];		\
			__entry->sequence = buf->sequence;		\
		),							\
									\
		TP_printk("minor = %d, index = %u, type = %s, "		\
			  "bytesused = %u, flags = %s, "		\
			  "field = %s, timestamp = %llu, timecode = { "	\
			  "type = %s, flags = %s, frames = %u, "	\
			  "seconds = %u, minutes = %u, hours = %u, "	\
			  "userbits = { %u %u %u %u } }, "		\
			  "sequence = %u", __entry->minor,		\
			  __entry->index, show_type(__entry->type),	\
			  __entry->bytesused,				\
			  show_flags(__entry->flags),			\
			  show_field(__entry->field),			\
			  __entry->timestamp,				\
			  show_timecode_type(__entry->timecode_type),	\
			  show_timecode_flags(__entry->timecode_flags),	\
			  __entry->timecode_frames,			\
			  __entry->timecode_seconds,			\
			  __entry->timecode_minutes,			\
			  __entry->timecode_hours,			\
			  __entry->timecode_userbits0,			\
			  __entry->timecode_userbits1,			\
			  __entry->timecode_userbits2,			\
			  __entry->timecode_userbits3,			\
			  __entry->sequence				\
		)							\
	)

V4L2_TRACE_EVENT(v4l2_dqbuf);
V4L2_TRACE_EVENT(v4l2_qbuf);

#endif /* if !defined(_TRACE_V4L2_H) || defined(TRACE_HEADER_MULTI_READ) */

/* This part must be outside protection */
#include <trace/define_trace.h>
