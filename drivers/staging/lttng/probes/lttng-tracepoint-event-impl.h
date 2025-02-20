/* 2017-05-30: File added by Sony Corporation */
/*
 * lttng-tracepoint-event-impl.h
 *
 * Copyright (C) 2009 Steven Rostedt <rostedt@goodmis.org>
 * Copyright (C) 2009-2014 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/rculist.h>
#include <asm/byteorder.h>
#include <linux/swab.h>

#include <probes/lttng.h>
#include <probes/lttng-types.h>
#include <probes/lttng-probe-user.h>
#include <wrapper/vmalloc.h>	/* for wrapper_vmalloc_sync_all() */
#include <wrapper/ringbuffer/frontend_types.h>
#include <wrapper/ringbuffer/backend.h>
#include <wrapper/rcu.h>
#include <lttng-events.h>
#include <lttng-tracer-core.h>

#define __LTTNG_NULL_STRING	"(null)"

/*
 * Macro declarations used for all stages.
 */

/*
 * LTTng name mapping macros. LTTng remaps some of the kernel events to
 * enforce name-spacing.
 */
#undef LTTNG_TRACEPOINT_EVENT_MAP
#define LTTNG_TRACEPOINT_EVENT_MAP(name, map, proto, args, fields) \
	LTTNG_TRACEPOINT_EVENT_CLASS(map,				\
			     PARAMS(proto),				\
			     PARAMS(args),				\
			     PARAMS(fields))				\
	LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP(map, name, map, PARAMS(proto), PARAMS(args))

#undef LTTNG_TRACEPOINT_EVENT_MAP_NOARGS
#define LTTNG_TRACEPOINT_EVENT_MAP_NOARGS(name, map, fields)		\
	LTTNG_TRACEPOINT_EVENT_CLASS_NOARGS(map,			\
			     PARAMS(fields))				\
	LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(map, name, map)

#undef LTTNG_TRACEPOINT_EVENT_CODE_MAP
#define LTTNG_TRACEPOINT_EVENT_CODE_MAP(name, map, proto, args, _locvar, _code_pre, fields, _code_post) \
	LTTNG_TRACEPOINT_EVENT_CLASS_CODE(map,				\
			     PARAMS(proto),				\
			     PARAMS(args),				\
			     PARAMS(_locvar),				\
			     PARAMS(_code_pre),				\
			     PARAMS(fields),				\
			     PARAMS(_code_post))			\
	LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP(map, name, map, PARAMS(proto), PARAMS(args))

#undef LTTNG_TRACEPOINT_EVENT_CODE
#define LTTNG_TRACEPOINT_EVENT_CODE(name, proto, args, _locvar, _code_pre, fields, _code_post) \
	LTTNG_TRACEPOINT_EVENT_CODE_MAP(name, name,			\
			     PARAMS(proto),				\
			     PARAMS(args),				\
			     PARAMS(_locvar),				\
			     PARAMS(_code_pre),				\
			     PARAMS(fields),				\
			     PARAMS(_code_post))

/*
 * LTTNG_TRACEPOINT_EVENT_CLASS can be used to add a generic function
 * handlers for events. That is, if all events have the same parameters
 * and just have distinct trace points.  Each tracepoint can be defined
 * with LTTNG_TRACEPOINT_EVENT_INSTANCE and that will map the
 * LTTNG_TRACEPOINT_EVENT_CLASS to the tracepoint.
 *
 * LTTNG_TRACEPOINT_EVENT is a one to one mapping between tracepoint and
 * template.
 */

#undef LTTNG_TRACEPOINT_EVENT
#define LTTNG_TRACEPOINT_EVENT(name, proto, args, fields)		\
	LTTNG_TRACEPOINT_EVENT_MAP(name, name,				\
			PARAMS(proto),					\
			PARAMS(args),					\
			PARAMS(fields))

#undef LTTNG_TRACEPOINT_EVENT_NOARGS
#define LTTNG_TRACEPOINT_EVENT_NOARGS(name, fields)			\
	LTTNG_TRACEPOINT_EVENT_MAP_NOARGS(name, name, PARAMS(fields))

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE
#define LTTNG_TRACEPOINT_EVENT_INSTANCE(template, name, proto, args)	\
	LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP(template, name, name, PARAMS(proto), PARAMS(args))

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_NOARGS(template, name)	\
	LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(template, name, name)

#undef LTTNG_TRACEPOINT_EVENT_CLASS
#define LTTNG_TRACEPOINT_EVENT_CLASS(_name, _proto, _args, _fields) \
	LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, PARAMS(_proto), PARAMS(_args), , , \
		PARAMS(_fields), )

#undef LTTNG_TRACEPOINT_EVENT_CLASS_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_NOARGS(_name, _fields) \
	LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, , , PARAMS(_fields), )


/*
 * Stage 1 of the trace events.
 *
 * Create dummy trace calls for each events, verifying that the LTTng module
 * instrumentation headers match the kernel arguments. Will be optimized
 * out by the compiler.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <probes/lttng-events-reset.h>

#undef TP_PROTO
#define TP_PROTO(...)	__VA_ARGS__

#undef TP_ARGS
#define TP_ARGS(...)	__VA_ARGS__

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP(_template, _name, _map, _proto, _args) \
void trace_##_name(_proto);

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(_template, _name, _map) \
void trace_##_name(void);

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/*
 * Stage 1.1 of the trace events.
 *
 * Create dummy trace prototypes for each event class, and for each used
 * template. This will allow checking whether the prototypes from the
 * class and the instance using the class actually match.
 */

#include <probes/lttng-events-reset.h>	/* Reset all macros within TRACE_EVENT */

#undef TP_PROTO
#define TP_PROTO(...)	__VA_ARGS__

#undef TP_ARGS
#define TP_ARGS(...)	__VA_ARGS__

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP(_template, _name, _map, _proto, _args) \
void __event_template_proto___##_template(_proto);

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(_template, _name, _map) \
void __event_template_proto___##_template(void);

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, _proto, _args, _locvar, _code_pre, _fields, _code_post) \
void __event_template_proto___##_name(_proto);

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, _fields, _code_post) \
void __event_template_proto___##_name(void);

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/*
 * Stage 2 of the trace events.
 *
 * Create event field type metadata section.
 * Each event produce an array of fields.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <probes/lttng-events-reset.h>
#include <probes/lttng-events-write.h>
#include <probes/lttng-events-nowrite.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _user, _nowrite) \
	{							\
	  .name = #_item,					\
	  .type = __type_integer(_type, 0, 0, -1, _byte_order, _base, none),\
	  .nowrite = _nowrite,					\
	  .user = _user,					\
	},

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _user, _nowrite) \
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_array,				\
		  .u =						\
			{					\
			  .array =				\
				{				\
				  .elem_type = __type_integer(_type, 0, 0, 0, __BYTE_ORDER, 10, _encoding), \
				  .length = _length,		\
				}				\
			}					\
		},						\
	  .nowrite = _nowrite,					\
	  .user = _user,					\
	},

#undef _ctf_array_bitfield
#define _ctf_array_bitfield(_type, _item, _src, _length, _user, _nowrite) \
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_array,				\
		  .u =						\
			{					\
			  .array =				\
				{				\
				  .elem_type = __type_integer(_type, 1, 1, 0, __LITTLE_ENDIAN, 10, none), \
				  .length = (_length) * sizeof(_type) * CHAR_BIT, \
				  .elem_alignment = lttng_alignof(_type), \
				}				\
			}					\
		},						\
	  .nowrite = _nowrite,					\
	  .user = _user,					\
	},


#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src,		\
			_length_type, _src_length, _encoding,	\
			_byte_order, _base, _user, _nowrite)	\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_sequence,			\
		  .u =						\
			{					\
			  .sequence =				\
				{				\
				  .length_type = __type_integer(_length_type, 0, 0, 0, __BYTE_ORDER, 10, none), \
				  .elem_type = __type_integer(_type, 0, 0, -1, _byte_order, _base, _encoding), \
				},				\
			},					\
		},						\
	  .nowrite = _nowrite,					\
	  .user = _user,					\
	},

#undef _ctf_sequence_bitfield
#define _ctf_sequence_bitfield(_type, _item, _src,		\
			_length_type, _src_length,		\
			_user, _nowrite)			\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_sequence,			\
		  .u =						\
			{					\
			  .sequence =				\
				{				\
				  .length_type = __type_integer(_length_type, 0, 0, 0, __BYTE_ORDER, 10, none), \
				  .elem_type = __type_integer(_type, 1, 1, 0, __LITTLE_ENDIAN, 10, none), \
				  .elem_alignment = lttng_alignof(_type), \
				},				\
			},					\
		},						\
	  .nowrite = _nowrite,					\
	  .user = _user,					\
	},

#undef _ctf_string
#define _ctf_string(_item, _src, _user, _nowrite)		\
	{							\
	  .name = #_item,					\
	  .type =						\
		{						\
		  .atype = atype_string,			\
		  .u =						\
			{					\
			  .basic = { .string = { .encoding = lttng_encode_UTF8 } } \
			},					\
		},						\
	  .nowrite = _nowrite,					\
	  .user = _user,					\
	},

#undef TP_FIELDS
#define TP_FIELDS(...)	__VA_ARGS__	/* Only one used in this phase */

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, _fields, _code_post) \
	static const struct lttng_event_field __event_fields___##_name[] = { \
		_fields							     \
	};

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, _proto, _args, _locvar, _code_pre, _fields, _code_post) \
	LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, PARAMS(_fields), _code_post)

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/*
 * Stage 3 of the trace events.
 *
 * Create probe callback prototypes.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <probes/lttng-events-reset.h>

#undef TP_PROTO
#define TP_PROTO(...)	__VA_ARGS__

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, _proto, _args, _locvar, _code_pre, _fields, _code_post) \
static void __event_probe__##_name(void *__data, _proto);

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, _fields, _code_post) \
static void __event_probe__##_name(void *__data);

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/*
 * Stage 4 of the trace events.
 *
 * Create static inline function that calculates event size.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <probes/lttng-events-reset.h>
#include <probes/lttng-events-write.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _user, _nowrite) \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type);

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _user, _nowrite) \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__event_len += sizeof(_type) * (_length);

#undef _ctf_array_bitfield
#define _ctf_array_bitfield(_type, _item, _src, _length, _user, _nowrite) \
	_ctf_array_encoded(_type, _item, _src, _length, none, _user, _nowrite)

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,			\
			_src_length, _encoding, _byte_order, _base, _user, _nowrite) \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_length_type)); \
	__event_len += sizeof(_length_type);				       \
	__event_len += lib_ring_buffer_align(__event_len, lttng_alignof(_type)); \
	__dynamic_len[__dynamic_len_idx] = (_src_length);		       \
	__event_len += sizeof(_type) * __dynamic_len[__dynamic_len_idx];       \
	__dynamic_len_idx++;

#undef _ctf_sequence_bitfield
#define _ctf_sequence_bitfield(_type, _item, _src,		\
			_length_type, _src_length,		\
			_user, _nowrite)			\
	_ctf_sequence_encoded(_type, _item, _src, _length_type, _src_length, \
		none, __LITTLE_ENDIAN, 10, _user, _nowrite)

/*
 * ctf_user_string includes \0. If returns 0, it faulted, so we set size to
 * 1 (\0 only).
 */
#undef _ctf_string
#define _ctf_string(_item, _src, _user, _nowrite)			       \
	if (_user)							       \
		__event_len += __dynamic_len[__dynamic_len_idx++] =	       \
			max_t(size_t, lttng_strlen_user_inatomic(_src), 1);    \
	else								       \
		__event_len += __dynamic_len[__dynamic_len_idx++] =	       \
			strlen((_src) ? (_src) : __LTTNG_NULL_STRING) + 1;

#undef TP_PROTO
#define TP_PROTO(...)	__VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...)	__VA_ARGS__

#undef TP_locvar
#define TP_locvar(...)	__VA_ARGS__

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, _proto, _args, _locvar, _code_pre, _fields, _code_post) \
static inline size_t __event_get_size__##_name(size_t *__dynamic_len,	      \
		void *__tp_locvar, _proto)				      \
{									      \
	size_t __event_len = 0;						      \
	unsigned int __dynamic_len_idx __attribute__((unused)) = 0;	      \
	struct { _locvar } *tp_locvar __attribute__((unused)) = __tp_locvar;  \
									      \
	_fields								      \
	return __event_len;						      \
}

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, _fields, _code_post) \
static inline size_t __event_get_size__##_name(size_t *__dynamic_len,	      \
		void *__tp_locvar)					      \
{									      \
	size_t __event_len = 0;						      \
	unsigned int __dynamic_len_idx __attribute__((unused)) = 0;	      \
	struct { _locvar } *tp_locvar __attribute__((unused)) = __tp_locvar;  \
									      \
	_fields								      \
	return __event_len;						      \
}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)


/*
 * Stage 4.1 of tracepoint event generation.
 *
 * Create static inline function that layout the filter stack data.
 * We make both write and nowrite data available to the filter.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <probes/lttng-events-reset.h>
#include <probes/lttng-events-write.h>
#include <probes/lttng-events-nowrite.h>

#undef _ctf_integer_ext_fetched
#define _ctf_integer_ext_fetched(_type, _item, _src, _byte_order, _base, _nowrite) \
	if (lttng_is_signed_type(_type)) {				       \
		int64_t __ctf_tmp_int64;				       \
		switch (sizeof(_type)) {				       \
		case 1:							       \
		{							       \
			union { _type t; int8_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 2:							       \
		{							       \
			union { _type t; int16_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != __BYTE_ORDER)		       \
				__swab16s(&__tmp.v);			       \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 4:							       \
		{							       \
			union { _type t; int32_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != __BYTE_ORDER)		       \
				__swab32s(&__tmp.v);			       \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 8:							       \
		{							       \
			union { _type t; int64_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != __BYTE_ORDER)		       \
				__swab64s(&__tmp.v);			       \
			__ctf_tmp_int64 = (int64_t) __tmp.v;		       \
			break;						       \
		}							       \
		default:						       \
			BUG_ON(1);					       \
		};							       \
		memcpy(__stack_data, &__ctf_tmp_int64, sizeof(int64_t));       \
	} else {							       \
		uint64_t __ctf_tmp_uint64;				       \
		switch (sizeof(_type)) {				       \
		case 1:							       \
		{							       \
			union { _type t; uint8_t v; } __tmp = { (_type) (_src) }; \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 2:							       \
		{							       \
			union { _type t; uint16_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != __BYTE_ORDER)		       \
				__swab16s(&__tmp.v);			       \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 4:							       \
		{							       \
			union { _type t; uint32_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != __BYTE_ORDER)		       \
				__swab32s(&__tmp.v);			       \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		case 8:							       \
		{							       \
			union { _type t; uint64_t v; } __tmp = { (_type) (_src) }; \
			if (_byte_order != __BYTE_ORDER)		       \
				__swab64s(&__tmp.v);			       \
			__ctf_tmp_uint64 = (uint64_t) __tmp.v;		       \
			break;						       \
		}							       \
		default:						       \
			BUG_ON(1);					       \
		};							       \
		memcpy(__stack_data, &__ctf_tmp_uint64, sizeof(uint64_t));     \
	}								       \
	__stack_data += sizeof(int64_t);

#undef _ctf_integer_ext_isuser0
#define _ctf_integer_ext_isuser0(_type, _item, _src, _byte_order, _base, _nowrite) \
	_ctf_integer_ext_fetched(_type, _item, _src, _byte_order, _base, _nowrite)

#undef _ctf_integer_ext_isuser1
#define _ctf_integer_ext_isuser1(_type, _item, _user_src, _byte_order, _base, _nowrite) \
{											\
	union {										\
		char __array[sizeof(_user_src)];					\
		__typeof__(_user_src) __v;						\
	} __tmp_fetch;									\
	if (lib_ring_buffer_copy_from_user_check_nofault(__tmp_fetch.__array,		\
				&(_user_src), sizeof(_user_src))) 			\
		memset(__tmp_fetch.__array, 0, sizeof(__tmp_fetch.__array));		\
	_ctf_integer_ext_fetched(_type, _item, __tmp_fetch.__v, _byte_order, _base, _nowrite) \
}

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _user_src, _byte_order, _base, _user, _nowrite) \
	_ctf_integer_ext_isuser##_user(_type, _item, _user_src, _byte_order, _base, _nowrite)

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _user, _nowrite) \
	{								       \
		unsigned long __ctf_tmp_ulong = (unsigned long) (_length);     \
		const void *__ctf_tmp_ptr = (_src);			       \
		memcpy(__stack_data, &__ctf_tmp_ulong, sizeof(unsigned long)); \
		__stack_data += sizeof(unsigned long);			       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef _ctf_array_bitfield
#define _ctf_array_bitfield(_type, _item, _src, _length, _user, _nowrite) \
	_ctf_array_encoded(_type, _item, _src, _length, none, _user, _nowrite)

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,		       \
			_src_length, _encoding, _byte_order, _base, _user, _nowrite) \
	{								       \
		unsigned long __ctf_tmp_ulong = (unsigned long) (_src_length); \
		const void *__ctf_tmp_ptr = (_src);			       \
		memcpy(__stack_data, &__ctf_tmp_ulong, sizeof(unsigned long)); \
		__stack_data += sizeof(unsigned long);			       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef _ctf_sequence_bitfield
#define _ctf_sequence_bitfield(_type, _item, _src,		\
			_length_type, _src_length,		\
			_user, _nowrite)			\
	_ctf_sequence_encoded(_type, _item, _src, _length_type, _src_length, \
		none, __LITTLE_ENDIAN, 10, _user, _nowrite)

#undef _ctf_string
#define _ctf_string(_item, _src, _user, _nowrite)			       \
	{								       \
		const void *__ctf_tmp_ptr =				       \
			((_src) ? (_src) : __LTTNG_NULL_STRING);	       \
		memcpy(__stack_data, &__ctf_tmp_ptr, sizeof(void *));	       \
		__stack_data += sizeof(void *);				       \
	}

#undef TP_PROTO
#define TP_PROTO(...) __VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...) __VA_ARGS__

#undef TP_locvar
#define TP_locvar(...)	__VA_ARGS__

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, _fields, _code_post) \
static inline								      \
void __event_prepare_filter_stack__##_name(char *__stack_data,		      \
		void *__tp_locvar)					      \
{									      \
	struct { _locvar } *tp_locvar __attribute__((unused)) = __tp_locvar;  \
									      \
	_fields								      \
}

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, _proto, _args, _locvar, _code_pre, _fields, _code_post) \
static inline								      \
void __event_prepare_filter_stack__##_name(char *__stack_data,		      \
		void *__tp_locvar, _proto)				      \
{									      \
	struct { _locvar } *tp_locvar __attribute__((unused)) = __tp_locvar;  \
									      \
	_fields								      \
}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/*
 * Stage 5 of the trace events.
 *
 * Create static inline function that calculates event payload alignment.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <probes/lttng-events-reset.h>
#include <probes/lttng-events-write.h>

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _src, _byte_order, _base, _user, _nowrite) \
	__event_align = max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _user, _nowrite) \
	__event_align = max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_array_bitfield
#define _ctf_array_bitfield(_type, _item, _src, _length, _user, _nowrite) \
	_ctf_array_encoded(_type, _item, _src, _length, none, _user, _nowrite)

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,			\
			_src_length, _encoding, _byte_order, _base, _user, _nowrite) \
	__event_align = max_t(size_t, __event_align, lttng_alignof(_length_type)); \
	__event_align = max_t(size_t, __event_align, lttng_alignof(_type));

#undef _ctf_sequence_bitfield
#define _ctf_sequence_bitfield(_type, _item, _src,		\
			_length_type, _src_length,		\
			_user, _nowrite)			\
	_ctf_sequence_encoded(_type, _item, _src, _length_type, _src_length, \
		none, __LITTLE_ENDIAN, 10, _user, _nowrite)

#undef _ctf_string
#define _ctf_string(_item, _src, _user, _nowrite)

#undef TP_PROTO
#define TP_PROTO(...)	__VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...)	__VA_ARGS__

#undef TP_locvar
#define TP_locvar(...)	__VA_ARGS__

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, _proto, _args, _locvar, _code_pre, _fields, _code_post) \
static inline size_t __event_get_align__##_name(void *__tp_locvar, _proto)    \
{									      \
	size_t __event_align = 1;					      \
	struct { _locvar } *tp_locvar __attribute__((unused)) = __tp_locvar;  \
									      \
	_fields								      \
	return __event_align;						      \
}

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, _fields, _code_post) \
static inline size_t __event_get_align__##_name(void *__tp_locvar)	      \
{									      \
	size_t __event_align = 1;					      \
	struct { _locvar } *tp_locvar __attribute__((unused)) = __tp_locvar;  \
									      \
	_fields								      \
	return __event_align;						      \
}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/*
 * Stage 6 of tracepoint event generation.
 *
 * Create the probe function. This function calls event size calculation
 * and writes event data into the buffer.
 */

/* Reset all macros within TRACEPOINT_EVENT */
#include <probes/lttng-events-reset.h>
#include <probes/lttng-events-write.h>

#undef _ctf_integer_ext_fetched
#define _ctf_integer_ext_fetched(_type, _item, _src, _byte_order, _base, _nowrite) \
	{								\
		_type __tmp = _src;					\
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(__tmp));\
		__chan->ops->event_write(&__ctx, &__tmp, sizeof(__tmp));\
	}

#undef _ctf_integer_ext_isuser0
#define _ctf_integer_ext_isuser0(_type, _item, _src, _byte_order, _base, _nowrite) \
	_ctf_integer_ext_fetched(_type, _item, _src, _byte_order, _base, _nowrite)

#undef _ctf_integer_ext_isuser1
#define _ctf_integer_ext_isuser1(_type, _item, _user_src, _byte_order, _base, _nowrite) \
{									       \
	union {										\
		char __array[sizeof(_user_src)];					\
		__typeof__(_user_src) __v;						\
	} __tmp_fetch;									\
	if (lib_ring_buffer_copy_from_user_check_nofault(__tmp_fetch.__array,		\
				&(_user_src), sizeof(_user_src))) 			\
		memset(__tmp_fetch.__array, 0, sizeof(__tmp_fetch.__array));		\
	_ctf_integer_ext_fetched(_type, _item, __tmp_fetch.__v, _byte_order, _base, _nowrite) \
}

#undef _ctf_integer_ext
#define _ctf_integer_ext(_type, _item, _user_src, _byte_order, _base, _user, _nowrite) \
	_ctf_integer_ext_isuser##_user(_type, _item, _user_src, _byte_order, _base, _nowrite)

#undef _ctf_array_encoded
#define _ctf_array_encoded(_type, _item, _src, _length, _encoding, _user, _nowrite) \
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	if (_user) {							\
		__chan->ops->event_write_from_user(&__ctx, _src, sizeof(_type) * (_length)); \
	} else {							\
		__chan->ops->event_write(&__ctx, _src, sizeof(_type) * (_length)); \
	}

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#undef _ctf_array_bitfield
#define _ctf_array_bitfield(_type, _item, _src, _length, _user, _nowrite) \
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	if (_user) {							\
		__chan->ops->event_write_from_user(&__ctx, _src, sizeof(_type) * (_length)); \
	} else {							\
		__chan->ops->event_write(&__ctx, _src, sizeof(_type) * (_length)); \
	}
#else /* #if (__BYTE_ORDER == __LITTLE_ENDIAN) */
/*
 * For big endian, we need to byteswap into little endian.
 */
#undef _ctf_array_bitfield
#define _ctf_array_bitfield(_type, _item, _src, _length, _user, _nowrite) \
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	{								\
		size_t _i;						\
									\
		for (_i = 0; _i < (_length); _i++) {			\
			_type _tmp;					\
									\
			if (_user) {					\
				if (get_user(_tmp, (_type *) _src + _i)) \
					_tmp = 0;			\
			} else {					\
				_tmp = ((_type *) _src)[_i];		\
			}						\
			switch (sizeof(_type)) {			\
			case 1:						\
				break;					\
			case 2:						\
				_tmp = cpu_to_le16(_tmp);		\
				break;					\
			case 4:						\
				_tmp = cpu_to_le32(_tmp);		\
				break;					\
			case 8:						\
				_tmp = cpu_to_le64(_tmp);		\
				break;					\
			default:					\
				BUG_ON(1);				\
			}						\
			__chan->ops->event_write(&__ctx, &_tmp, sizeof(_type)); \
		}							\
	}
#endif /* #else #if (__BYTE_ORDER == __LITTLE_ENDIAN) */

#undef _ctf_sequence_encoded
#define _ctf_sequence_encoded(_type, _item, _src, _length_type,		\
			_src_length, _encoding, _byte_order, _base, _user, _nowrite) \
	{								\
		_length_type __tmpl = __stackvar.__dynamic_len[__dynamic_len_idx]; \
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_length_type));\
		__chan->ops->event_write(&__ctx, &__tmpl, sizeof(_length_type));\
	}								\
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	if (_user) {							\
		__chan->ops->event_write_from_user(&__ctx, _src,	\
			sizeof(_type) * __get_dynamic_len(dest));	\
	} else {							\
		__chan->ops->event_write(&__ctx, _src,			\
			sizeof(_type) * __get_dynamic_len(dest));	\
	}

#if (__BYTE_ORDER == __LITTLE_ENDIAN)
#undef _ctf_sequence_bitfield
#define _ctf_sequence_bitfield(_type, _item, _src,		\
			_length_type, _src_length,		\
			_user, _nowrite)			\
	{								\
		_length_type __tmpl = __stackvar.__dynamic_len[__dynamic_len_idx] * sizeof(_type) * CHAR_BIT; \
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_length_type));\
		__chan->ops->event_write(&__ctx, &__tmpl, sizeof(_length_type));\
	}								\
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	if (_user) {							\
		__chan->ops->event_write_from_user(&__ctx, _src,	\
			sizeof(_type) * __get_dynamic_len(dest));	\
	} else {							\
		__chan->ops->event_write(&__ctx, _src,			\
			sizeof(_type) * __get_dynamic_len(dest));	\
	}
#else /* #if (__BYTE_ORDER == __LITTLE_ENDIAN) */
/*
 * For big endian, we need to byteswap into little endian.
 */
#undef _ctf_sequence_bitfield
#define _ctf_sequence_bitfield(_type, _item, _src,		\
			_length_type, _src_length,		\
			_user, _nowrite)			\
	{							\
		_length_type __tmpl = __stackvar.__dynamic_len[__dynamic_len_idx] * sizeof(_type) * CHAR_BIT; \
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_length_type));\
		__chan->ops->event_write(&__ctx, &__tmpl, sizeof(_length_type));\
	}								\
	lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(_type));	\
	{								\
		size_t _i, _length;					\
									\
		_length = __get_dynamic_len(dest);			\
		for (_i = 0; _i < _length; _i++) {			\
			_type _tmp;					\
									\
			if (_user) {					\
				if (get_user(_tmp, (_type *) _src + _i)) \
					_tmp = 0;			\
			} else {					\
				_tmp = ((_type *) _src)[_i];		\
			}						\
			switch (sizeof(_type)) {			\
			case 1:						\
				break;					\
			case 2:						\
				_tmp = cpu_to_le16(_tmp);		\
				break;					\
			case 4:						\
				_tmp = cpu_to_le32(_tmp);		\
				break;					\
			case 8:						\
				_tmp = cpu_to_le64(_tmp);		\
				break;					\
			default:					\
				BUG_ON(1);				\
			}						\
			__chan->ops->event_write(&__ctx, &_tmp, sizeof(_type)); \
		}							\
	}
#endif /* #else #if (__BYTE_ORDER == __LITTLE_ENDIAN) */

#undef _ctf_string
#define _ctf_string(_item, _src, _user, _nowrite)		        \
	if (_user) {							\
		lib_ring_buffer_align_ctx(&__ctx, lttng_alignof(*(_src))); \
		__chan->ops->event_strcpy_from_user(&__ctx, _src,	\
			__get_dynamic_len(dest));			\
	} else {							\
		const char *__ctf_tmp_string =				\
			((_src) ? (_src) : __LTTNG_NULL_STRING);	\
		lib_ring_buffer_align_ctx(&__ctx,			\
			lttng_alignof(*__ctf_tmp_string));		\
		__chan->ops->event_strcpy(&__ctx, __ctf_tmp_string,	\
			__get_dynamic_len(dest));			\
	}

/* Beware: this get len actually consumes the len value */
#undef __get_dynamic_len
#define __get_dynamic_len(field)	__stackvar.__dynamic_len[__dynamic_len_idx++]

#undef TP_PROTO
#define TP_PROTO(...)	__VA_ARGS__

#undef TP_ARGS
#define TP_ARGS(...)	__VA_ARGS__

#undef TP_FIELDS
#define TP_FIELDS(...)	__VA_ARGS__

#undef TP_locvar
#define TP_locvar(...)	__VA_ARGS__

#undef TP_code_pre
#define TP_code_pre(...)	__VA_ARGS__

#undef TP_code_post
#define TP_code_post(...)	__VA_ARGS__

/*
 * For state dump, check that "session" argument (mandatory) matches the
 * session this event belongs to. Ensures that we write state dump data only
 * into the started session, not into all sessions.
 */
#ifdef TP_SESSION_CHECK
#define _TP_SESSION_CHECK(session, csession)	(session == csession)
#else /* TP_SESSION_CHECK */
#define _TP_SESSION_CHECK(session, csession)	1
#endif /* TP_SESSION_CHECK */

/*
 * Using twice size for filter stack data to hold size and pointer for
 * each field (worse case). For integers, max size required is 64-bit.
 * Same for double-precision floats. Those fit within
 * 2*sizeof(unsigned long) for all supported architectures.
 * Perform UNION (||) of filter runtime list.
 */
#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE(_name, _proto, _args, _locvar, _code_pre, _fields, _code_post) \
static void __event_probe__##_name(void *__data, _proto)		      \
{									      \
	struct probe_local_vars { _locvar };				      \
	struct lttng_event *__event = __data;				      \
	struct lttng_probe_ctx __lttng_probe_ctx = {				      \
		.event = __event,				              \
		.interruptible = !irqs_disabled(),			      \
	};								      \
	struct lttng_channel *__chan = __event->chan;			      \
	struct lttng_session *__session = __chan->session;		      \
	struct lib_ring_buffer_ctx __ctx;				      \
	size_t __event_len, __event_align;				      \
	size_t __dynamic_len_idx __attribute__((unused)) = 0;		      \
	union {								      \
		size_t __dynamic_len[ARRAY_SIZE(__event_fields___##_name)];   \
		char __filter_stack_data[2 * sizeof(unsigned long) * ARRAY_SIZE(__event_fields___##_name)]; \
	} __stackvar;							      \
	int __ret;							      \
	struct probe_local_vars __tp_locvar;				      \
	struct probe_local_vars *tp_locvar __attribute__((unused)) =	      \
			&__tp_locvar;					      \
	struct lttng_pid_tracker *__lpf;				      \
									      \
	if (!_TP_SESSION_CHECK(session, __session))			      \
		return;							      \
	if (unlikely(!ACCESS_ONCE(__session->active)))			      \
		return;							      \
	if (unlikely(!ACCESS_ONCE(__chan->enabled)))			      \
		return;							      \
	if (unlikely(!ACCESS_ONCE(__event->enabled)))			      \
		return;							      \
	__lpf = lttng_rcu_dereference(__session->pid_tracker);		      \
	if (__lpf && likely(!lttng_pid_tracker_lookup(__lpf, current->pid)))  \
		return;							      \
	_code_pre							      \
	if (unlikely(!list_empty(&__event->bytecode_runtime_head))) {	      \
		struct lttng_bytecode_runtime *bc_runtime;		      \
		int __filter_record = __event->has_enablers_without_bytecode; \
									      \
		__event_prepare_filter_stack__##_name(__stackvar.__filter_stack_data, \
				tp_locvar, _args);				      \
		lttng_list_for_each_entry_rcu(bc_runtime, &__event->bytecode_runtime_head, node) { \
			if (unlikely(bc_runtime->filter(bc_runtime, &__lttng_probe_ctx,	      \
					__stackvar.__filter_stack_data) & LTTNG_FILTER_RECORD_FLAG)) \
				__filter_record = 1;			      \
		}							      \
		if (likely(!__filter_record))				      \
			goto __post;					      \
	}								      \
	__event_len = __event_get_size__##_name(__stackvar.__dynamic_len,     \
				tp_locvar, _args);			      \
	__event_align = __event_get_align__##_name(tp_locvar, _args);         \
	lib_ring_buffer_ctx_init(&__ctx, __chan->chan, &__lttng_probe_ctx, __event_len,  \
				 __event_align, -1);			      \
	__ret = __chan->ops->event_reserve(&__ctx, __event->id);	      \
	if (__ret < 0)							      \
		goto __post;						      \
	_fields								      \
	__chan->ops->event_commit(&__ctx);				      \
__post:									      \
	_code_post							      \
	return;								      \
}

#undef LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS
#define LTTNG_TRACEPOINT_EVENT_CLASS_CODE_NOARGS(_name, _locvar, _code_pre, _fields, _code_post) \
static void __event_probe__##_name(void *__data)			      \
{									      \
	struct probe_local_vars { _locvar };				      \
	struct lttng_event *__event = __data;				      \
	struct lttng_probe_ctx __lttng_probe_ctx = {				      \
		.event = __event,				              \
		.interruptible = !irqs_disabled(),			      \
	};								      \
	struct lttng_channel *__chan = __event->chan;			      \
	struct lttng_session *__session = __chan->session;		      \
	struct lib_ring_buffer_ctx __ctx;				      \
	size_t __event_len, __event_align;				      \
	size_t __dynamic_len_idx __attribute__((unused)) = 0;		      \
	union {								      \
		size_t __dynamic_len[ARRAY_SIZE(__event_fields___##_name)];   \
		char __filter_stack_data[2 * sizeof(unsigned long) * ARRAY_SIZE(__event_fields___##_name)]; \
	} __stackvar;							      \
	int __ret;							      \
	struct probe_local_vars __tp_locvar;				      \
	struct probe_local_vars *tp_locvar __attribute__((unused)) =	      \
			&__tp_locvar;					      \
	struct lttng_pid_tracker *__lpf;				      \
									      \
	if (!_TP_SESSION_CHECK(session, __session))			      \
		return;							      \
	if (unlikely(!ACCESS_ONCE(__session->active)))			      \
		return;							      \
	if (unlikely(!ACCESS_ONCE(__chan->enabled)))			      \
		return;							      \
	if (unlikely(!ACCESS_ONCE(__event->enabled)))			      \
		return;							      \
	__lpf = lttng_rcu_dereference(__session->pid_tracker);		      \
	if (__lpf && likely(!lttng_pid_tracker_lookup(__lpf, current->pid)))  \
		return;							      \
	_code_pre							      \
	if (unlikely(!list_empty(&__event->bytecode_runtime_head))) {	      \
		struct lttng_bytecode_runtime *bc_runtime;		      \
		int __filter_record = __event->has_enablers_without_bytecode; \
									      \
		__event_prepare_filter_stack__##_name(__stackvar.__filter_stack_data, \
				tp_locvar);				      \
		lttng_list_for_each_entry_rcu(bc_runtime, &__event->bytecode_runtime_head, node) { \
			if (unlikely(bc_runtime->filter(bc_runtime, &__lttng_probe_ctx,	\
					__stackvar.__filter_stack_data) & LTTNG_FILTER_RECORD_FLAG)) \
				__filter_record = 1;			      \
		}							      \
		if (likely(!__filter_record))				      \
			goto __post;					      \
	}								      \
	__event_len = __event_get_size__##_name(__stackvar.__dynamic_len, tp_locvar); \
	__event_align = __event_get_align__##_name(tp_locvar);		      \
	lib_ring_buffer_ctx_init(&__ctx, __chan->chan, &__lttng_probe_ctx, __event_len,  \
				 __event_align, -1);			      \
	__ret = __chan->ops->event_reserve(&__ctx, __event->id);	      \
	if (__ret < 0)							      \
		goto __post;						      \
	_fields								      \
	__chan->ops->event_commit(&__ctx);				      \
__post:									      \
	_code_post							      \
	return;								      \
}

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

#undef __get_dynamic_len

/*
 * Stage 7 of the trace events.
 *
 * Create event descriptions.
 */

/* Named field types must be defined in lttng-types.h */

#include <probes/lttng-events-reset.h>	/* Reset all macros within LTTNG_TRACEPOINT_EVENT */

#ifndef TP_PROBE_CB
#define TP_PROBE_CB(_template)	&__event_probe__##_template
#endif

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(_template, _name, _map)	\
static const struct lttng_event_desc __event_desc___##_map = {		\
	.fields = __event_fields___##_template,		     		\
	.name = #_map,					     		\
	.kname = #_name,				     		\
	.probe_callback = (void *) TP_PROBE_CB(_template),   		\
	.nr_fields = ARRAY_SIZE(__event_fields___##_template),		\
	.owner = THIS_MODULE,				     		\
};

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP(_template, _name, _map, _proto, _args) \
	LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(_template, _name, _map)

#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)

/*
 * Stage 8 of the trace events.
 *
 * Create an array of event description pointers.
 */

#include <probes/lttng-events-reset.h>	/* Reset all macros within LTTNG_TRACEPOINT_EVENT */

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(_template, _name, _map) \
		&__event_desc___##_map,

#undef LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP
#define LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP(_template, _name, _map, _proto, _args) \
	LTTNG_TRACEPOINT_EVENT_INSTANCE_MAP_NOARGS(_template, _name, _map)

#define TP_ID1(_token, _system)	_token##_system
#define TP_ID(_token, _system)	TP_ID1(_token, _system)

static const struct lttng_event_desc *TP_ID(__event_desc___, TRACE_SYSTEM)[] = {
#include TRACE_INCLUDE(TRACE_INCLUDE_FILE)
};

#undef TP_ID1
#undef TP_ID

/*
 * Stage 9 of the trace events.
 *
 * Create a toplevel descriptor for the whole probe.
 */

#define TP_ID1(_token, _system)	_token##_system
#define TP_ID(_token, _system)	TP_ID1(_token, _system)

/* non-const because list head will be modified when registered. */
static __used struct lttng_probe_desc TP_ID(__probe_desc___, TRACE_SYSTEM) = {
	.provider = __stringify(TRACE_SYSTEM),
	.event_desc = TP_ID(__event_desc___, TRACE_SYSTEM),
	.nr_events = ARRAY_SIZE(TP_ID(__event_desc___, TRACE_SYSTEM)),
	.head = { NULL, NULL },
	.lazy_init_head = { NULL, NULL },
	.lazy = 0,
};

#undef TP_ID1
#undef TP_ID

/*
 * Stage 10 of the trace events.
 *
 * Register/unregister probes at module load/unload.
 */

#include <probes/lttng-events-reset.h>	/* Reset all macros within LTTNG_TRACEPOINT_EVENT */

#define TP_ID1(_token, _system)	_token##_system
#define TP_ID(_token, _system)	TP_ID1(_token, _system)
#define module_init_eval1(_token, _system)	module_init(_token##_system)
#define module_init_eval(_token, _system)	module_init_eval1(_token, _system)
#define module_exit_eval1(_token, _system)	module_exit(_token##_system)
#define module_exit_eval(_token, _system)	module_exit_eval1(_token, _system)

#ifndef TP_MODULE_NOINIT
static int TP_ID(__lttng_events_init__, TRACE_SYSTEM)(void)
{
	wrapper_vmalloc_sync_all();
	return lttng_probe_register(&TP_ID(__probe_desc___, TRACE_SYSTEM));
}

static void TP_ID(__lttng_events_exit__, TRACE_SYSTEM)(void)
{
	lttng_probe_unregister(&TP_ID(__probe_desc___, TRACE_SYSTEM));
}

#ifndef TP_MODULE_NOAUTOLOAD
module_init_eval(__lttng_events_init__, TRACE_SYSTEM);
module_exit_eval(__lttng_events_exit__, TRACE_SYSTEM);
#endif

#endif

#undef module_init_eval
#undef module_exit_eval
#undef TP_ID1
#undef TP_ID

#undef TP_PROTO
#undef TP_ARGS
