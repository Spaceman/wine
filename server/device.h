/*
 * Server-side device support
 *
 * Copyright (C) 2007 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#ifndef __WINE_SERVER_DEVICE_H
#define __WINE_SERVER_DEVICE_H

#include "wine/server_protocol.h"

struct process;
struct thread;

extern void dispatch_create_process_event( struct process *process );
extern void dispatch_terminate_process_event( struct process * process);
extern void dispatch_create_thread_event( struct thread *thread );
extern void dispatch_terminate_thread_event( struct thread *thread );
extern void dispatch_load_image_event( struct process *process, mod_handle_t base );

#endif  /* __WINE_SERVER_DEVICE_H */
