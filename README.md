# tokenLib::
The `tokenLib::` library was originaly developed by me for a [Shark Cage project](https://github.com/SharkCagey/HTWG_shark_cage) at HTWG university. Its purpose was to capture a token of user that is currently using a computer, modify it to add a local group present on the system to only this instance of the token (_i.e. without user becoming a member of said group_) to allow a certain programs to run with privileges attributed to that group.

Since then, it has been extracted from the project, moved into a standalone open-source project and distributed as a DLL to be used. Now it is possible to add multiple user groups and multiple privileges into a token. However, there are still some drawbacks that need to be addressed as well as some implementation challenges.

## Overview of functionality
The core of the library is a family of functions modifying token. These functions create a token that is exactly the same as the token of a user currently logged to a session that is attached to the physical console, but with selected modifications applied. Modification functions include:

- `constructUserTokenWithGroup()` : creates a token identical to the one of physical console, with one group added
- `constructUserTokenWithMultipleGroups()` : the same as above, but with multiple groups
- `constructUserTokenWithMultiplePrivileges()` : the same, but with privileges

The library also includes a set of auxialiary functions design to simplify its use:

- `aquireTokenWithPrivilegesForTokenManipulation()` : function designed to search the system for token with privileges neccessary to perform privilege manipulation
- `createLocalGroup()`, `deleteLocalGroup()`, `destroySid()` : these functions are a remnant of a time when the library was only used to add groups to the token, they need to stay as a legacy, to not break old projects using this APIs

### Expected usage workflow
Expected usage of the library is demonstrated the best in a two process environment (expressed chronologically):

**Process 1** (_Parent_):
- Uses `aquireTokenWithPrivilegesForTokenManipulation()` function to acquire a token with all the needed privileges.
- Starts a child process with the acquired token.

**Process 2** (_Child_):
- Creates (or uses one present in the system) a local group(s) or privilege(s) to be added to a token.
- obtains a modified token by invoking some of `constructUserTokenWith...()` functions.
- uses the obtained token for whatever it needs to be used.

It is, of course, possible to obtain privileges in **Process 2** any other viable way or to skip the two process procedure altogether, if the original process has all necessary privileges.

###  Neccessary privileges
To use the library and perform token modification, the following criteria must be met:

For token modification family of functions (`constructUserTokenWith...()`) to work, the library requires a special set of privileges and conditions to be satisfied:

- the process must hold `SeCreateTokenPrivilege` and `SeTcbPrivilege`
- the process must run under `LocalSystem` context

To achieve this state, a function `aquireTokenWithPrivilegesForTokenManipulation()` was created. It relies on a fact that at least one process in the system satisfies all the conditions needed. It goes through all the processes, finds the satisfactory process, acquires its token and returns a handle to a duplicate of such a process.

To call `aquireTokenWithPrivilegesForTokenManipulation()` function, calling process must have `SeDebugPrivilege`. Although, this is not a semantic requirement, the process must run under `LocalSystem` context, in order to obtain any useful result from the function call. (If not, processes under LocalSystem could not be accessed and `aquireTokenWithPrivilegesForTokenManipulation()` will think there are no processes in the system fulfilling all criteria)
