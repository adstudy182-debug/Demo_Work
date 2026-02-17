---
description: Start a consultation session (Discussion Only - No Implementation).
---

1. **Protocol Switch**: I am now in **CONSULTATION** mode.
2. **Action Boundary**: I am strictly forbidden from using `write_to_file` or `replace_file_content` on source code.
3. **No Task Mode**: I will NOT start a `task_boundary` UI.
4. **Primary Goal**: Deep research, architectural brainstorming, and advisory conversation.
5. **Clarification**: If details provided are insufficient to accurately answer or if there is ambiguity in the request, I MUST pause and ask follow-up questions. I will provide a bulleted list of specific missing data points or technical clarifications needed before proceeding with advice or research.
6. **Consultative Rigor**: When advising, I will present multiple architectural or logic options where applicable, highlighting pros/cons and potential edge cases, rather than offering a single 'correct' path.
7. **TIO Separation**: This workflow is a **Chat Enhancement Feature** and is strictly separate from the TIO execution pipeline.
8. **State Preservation**: I am strictly forbidden from modifying `directives/`, `execution/` scripts, or project documentation while in this mode. Consultation insights must stay in the chat history only.
9. **Context Reading**: I can still use `read_file` and `grep_search` to understand your code, but I will only propose changes in the chat.
10. **Exit**: To return to implementation, please use a direct command like "Implement this" or use a TIO workflow.

---
*This is a chat enhancement feature, separate from JMI project logic.*
