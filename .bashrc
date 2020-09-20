# .bashrc
# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi
umask 002
export HISTSIZE=10000
export HISTFILESIZE=200000

#already_running=`lsof | grep "$(ps | grep bash | cut -f 2 -d " ")" | grep script`

export PS1='\[\033[01;32m\][\u@\h\[\033[00m\] \[\033[01;34m\]\W]\[\033[00m\]\$ '
export HOME=/home/build
export CSCOPE_EDITOR=vim
export SVN_EDITOR=vim
#export PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:$HOME/bin:$HOME/.local/bin:$PATH
disabled=1
if [[  "$1" == "log" ]]; then
		disabled=0
		skip=l
fi
if [[ "$SCRIPT_FILE" == "" && $disabled -ne 1 ]]; then
#	echo "Press 'l' to start logging"
#	read -n 1 -d - -t 3 skip
#	if [[ "$skip" == "" && $? > 128 ]]; then
	if [[ "$skip" != "" ]]; then
			file=~/SessionLogs/script_$(date +%Y%m%d_%H%M%S)
			export SCRIPT_FILE=$file
		    script $file
			export -n SCRIPT_FILE
#			echo "Press any key to stop exiting"
#			read -t 5 quit
#			if [ "$quit" != "" ]; then
#					echo "Not exiting shell"
#			else
					exit
#			fi
	fi
fi

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# some more ls aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'



# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
source ~/.aliases
source ~/bin/setup_funcs
alias setup-bashrc='source ~/.bashrc'
export DPDK_CHECKPATCH_PATH=/home/build/bin/checkpatch.pl
export DPDK_GETMAINTAINER_PATH=/home/build/bin/get_maintainer.pl
# Experimental neovim
# alias vim=nvim
# export CSCOPE_EDITOR=nvim
# export SVN_EDITOR=nvim

alias vim=vim81
alias nano=nano43
export CSCOPE_EDITOR=vim81
export SVN_EDITOR=vim81
source ~/.git-completion.bash

# added by Anaconda3 4.2.0 installer
function setup_anaconda()
{
	export PATH="/home/build/anaconda3/bin:$PATH"
}

function setup_clang()
{
	export PATH="/home/build/os/llvm-project/build/bin:$PATH"
}
