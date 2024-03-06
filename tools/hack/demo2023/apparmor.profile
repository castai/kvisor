#include <tunables/global>

profile example_profile {
  #include <abstractions/base>

  /path/to/allowed/file rw,
  /path/to/allowed/directory/ rw,

  /path/to/denied/file ix,
  /path/to/denied/directory/** ix,

  # You can add more rules as needed.

  # Deny everything else by default
  /  ix,

  # Allow reading for some directories
  /etc/ r,
  /usr/ r,
  /var/ r,
  /lib/ r,
  /bin/ r,
  /sbin/ r,

  # Allow connecting to the network
  network,

  # Allow necessary capabilities
  capability,

  # Allow signals
  signal,

  # Allow ptrace for debugging
  ptrace,

  # Allow accessing /proc entries
  /proc/** r,

  # Allow access to shared libraries
  /usr/lib/** mr,
  /lib/** mr,

  # Allow access to system fonts
  /usr/share/fonts/** r,

  # Allow accessing user's home directory
  /home/[username]/ r,

  # Deny access to sensitive files
  deny /etc/shadow r,
  deny /etc/passwd r,
  deny /etc/gshadow r,
  deny /etc/group r,

  # Log denied access attempts
  audit deny /path/to/denied/file,
  audit deny /path/to/denied/directory/,

  # Tunables
  /etc/apparmor.d/tunables/home -> /home/,
  /etc/apparmor.d/tunables/proc -> /proc/,
}
