You’re working on an SSH-based chat app with an interactive terminal UI (PTY + raw-ish input handling). Fix these two terminal bugs:



1\. Broken newlines / paragraph alignment in server output

&nbsp;  Symptoms: multi-line strings (welcome text, `/help` output, etc.) render with the next line starting at the previous line’s column (or otherwise “shifted”), and long lines get split oddly. This is typical when the PTY is put into raw mode (e.g., via `term.MakeRaw`) and `\\n` is no longer translated to `\\r\\n`.

&nbsp;  Fix: ensure all server-to-client text output uses correct CRLF semantics. Centralize writes through a single helper/writer that:



\* converts every `\\n` to `\\r\\n` (and avoids double-converting existing `\\r\\n`)

\* ensures lines start at column 0 when appropriate (often by prefixing with `\\r` before printing new content)

\* avoids interleaving output from concurrent goroutines (use a mutex or a single output goroutine)



Also make sure printing command responses doesn’t corrupt the prompt/input line: clear the current input line, print output, then re-render the prompt + current input buffer.



2\. Input editor hard-wraps at 80 columns

&nbsp;  Symptoms: while the user is typing, their input is forcibly wrapped at 80 columns even if the terminal is wider (e.g., 120). Incoming messages don’t have this issue.

&nbsp;  Fix: remove any hard-coded “80 columns” assumption in the line editor / wrapping logic. Use the actual PTY width for the session (from the SSH PTY/window size) and update it on resize (`window-change` requests). The input editor (cursor position, redraw, wrapping) must respect the current terminal width.



Acceptance criteria:



\* Welcome text and `/help` output render as clean multi-line paragraphs with correct line starts (no shifted paragraphs, no weird splits caused by missing `\\r`).

\* While typing a long line in a wide terminal, the client does not receive hard-inserted line breaks at 80; wrapping matches the actual terminal width and behaves consistently across resizes.

\* Prompt/input line remains intact after printing asynchronous chat messages or command output (no overwritten/misaligned prompt).



Add minimal regression coverage where feasible (unit tests for newline normalization and width-based wrapping/redraw math, and/or a small manual test note).

If this library for terminal you use needs a different approach to fix the bug, go as it's appropriate. I told you how to fix it from print / fmt perspective.



Also, fix this bugs / implement features

1\. fix command aliases / duplicates to not interfere with eachother.

/users #roomname must view users in that room. In all commands, in the place of the room if you type "." it means that room that i am now. And where user, @me is me.  @everyone mentiones everyone.

2\. if this feature needs terminal hacks, don't implement it. Make hotkeys for some commands, escape for exiting as well as ctrl+c, ctrl+backspace for deleting a word if this is not a terminal hack to implement, ctrl+tab to join the general room from somewhere else.

3\. if not implemented, admins must receive join and leave alert for all users, even if not joined to the room the admin is currently. People must receive notifications that someone joined and left there room that they are currently in, not the room that he created.



