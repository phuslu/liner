if [[ " screen-256color tmux-256color xterm-256color xterm-color xterm screen rxvt " == *" $TERM "* ]]; then
    export PS1='\[\e]0;\h:\w\a\]\n\[\e[1;32m\]\u@\H\[\e[0;33m\] \w \[\e[0m[\D{%T}]\n\[\e[1;$((31+3*!$?))m\]\$\[\e[0m\] '
fi

if [[ $- == *i* ]]; then
    bind "\e[1~": beginning-of-line
    bind "\e[4~": end-of-line
    bind "\e[5~": previous-screen
    bind "\e[6~": next-screen
    bind "\e[F": end-of-line
    bind "\e[H": beginning-of-line
    bind "\eOF": end-of-line
    bind "\eOH": beginning-of-line
    bind "\e[B": history-search-forward
    bind "\e[A": history-search-backward
fi

export LC_ALL=en_US.UTF-8
export TERM=xterm-256color
export SHELL=/bin/bash
export PATH=~/.local/bin:~/.venv/bin:$HOME/Library/Python/3.9/bin:/sbin:/usr/sbin:$PATH

alias ls='ls -p --color'
alias ll='ls -lF --color'
alias rm='rm -i'
alias mv='mv -i'
alias cp='cp -i'
alias grep='grep --color'
alias tailf='tail -F'
