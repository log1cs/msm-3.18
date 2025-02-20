/* 2017-04-24: File added by Sony Corporation */
/*
 *  Copyright 2011 Sony Corporation.
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  version 2 of the  License.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMITED  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE    LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, write  to the Free Software Foundation, Inc.,
 *  675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __SNSC_BACKTRACE_IOCTL_H__
#define __SNSC_BACKTRACE_IOCTL_H__
//#include <linux/compiler.h>
#include <linux/ioctl.h>

struct bt_ioctl_addrs {
	void ** ba_buf;
	int ba_size;
	void * ba_skip_addr;
};

struct bt_ioctl_symbol {
	void * bs_addr;
	char * bs_buf;
	int bs_size;
};

/* 0xff is not reserved according to Documentation/ioctl/ioctl-number.txt */
#define BT_IOCTL_ADDRS _IOWR(0xff,1,struct bt_ioctl_addrs)
#define BT_IOCTL_SYMBOL _IOWR(0xff,2,struct bt_ioctl_symbol)

#endif
