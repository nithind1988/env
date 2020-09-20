set editor = `echo \$EDITOR`
set imap_user='nithind1988@gmail.com'
set from="Nithin Dabilpuram <nithind1988@gmail.com>"
set hostname="gmail.com"
set folder="imaps://imap.gmail.com:993/"
set postponed="=Drafts"
set spoolfile="imaps://imap.gmail.com/ml/lkml"
set smtp_url="smtp://$imap_user:$imap_pass@smtp.gmail.com"
unset imap_passive
set imap_keepalive = 300
set mail_check = 120
set sort=threads
set sort_aux=last-date-received
set collapse_unread
set ssl_starttls = yes
set ssl_force_tls = yes
set header_cache = "~/~/.muttcache2/"
set message_cachedir = "~/.muttcache2/"
set certificate_file = ~/.mutt/certificates
set imap_qresync = yes
set imap_condstore = yes
set imap_fetch_chunk_size = 32
set imap_fetch_chunk_size = 32

#pass from gnome keyring

source ~/.mutt/mutt_shortcuts
set pager_index_lines   = 30

set my_name = '<nithind1988@gmail.com>'


macro index TN '<collapse-all><tag-pattern> ~s $my_netignore'

set timeout = 60
timeout-hook . "exec sync-mailbox"
