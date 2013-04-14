/* constants.h: Architectural and other constants
  ------------------------------------------------------------------------------

   Copyright (c) 2012, Robert M. A. Jarratt
 
   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
   THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

   Except as contained in this notice, the name of the author shall not be
   used in advertising or otherwise to promote the sale, use or other dealings
   in this Software without prior written authorization from the author.

  ------------------------------------------------------------------------------*/

#if !defined(CONSTANTS_H)

#define BCT3MULT   3
#define NA        63
#define NN      1023
#define NC        16
#define NBRA      33
#define NBEA    1024
#define DRDELAY    5
#define Infh      31
#define Infc    1023
#define Maxl      25
#define Maxc    1022
#define Maxh      30
#define Maxv      31
#define AMaxc   1022
#define AMaxh     30
#define T1       600
#define BCT1     180
#define T2         1

#define LEVEL1_BATCH_SIZE 32 /* must be integral factor of NN + 1 */

#define MAX_DATA_MESSAGE_BODY_SIZE 8192
#define MAX_LOG_LINE_LEN 800
#define CONFIG_FILE_NAME "route20.ini"

#define NSP_SEGMENT_SIZE 1459

#define CONSTANTS_H
#endif
