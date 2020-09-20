" Vim plugin to fit the GNU coding style and help kernel development
"
" This script is inspired from an article written by Bart:
" http://www.jukie.net/bart/blog/vim-and-linux-coding-style
" and various user comments.
"
"let g:gnusty_patterns = [ "/linux/", "/kernel/" ]

if exists("g:loaded_gnusty")
    finish
endif
let g:loaded_gnusty = 1

set wildignore+=*.ko,*.mod.c,*.order,modules.builtin

augroup gnusty
    autocmd!

    autocmd FileType c,cpp call s:GNUConfigure()
    autocmd FileType diff,kconfig setlocal tabstop=8
augroup END

function s:GNUConfigure()
    let apply_style = 0

    if exists("g:gnusty_patterns")
        let path = expand('%:p')
        for p in g:gnusty_patterns
            if path =~ p
                let apply_style = 1
                break
            endif
        endfor
    endif

    if apply_style
        call s:GNUCodingStyle()
    endif
endfunction

command! GNUCodingStyle call s:GNUCodingStyle()

function! s:GNUCodingStyle()
    let b:StyleString="GNUC"
    call s:GNUFormatting()
    call s:GNUKeywords()
    call s:GNUHighlighting()
endfunction

function s:GNUFormatting()
	setlocal cindent
	setlocal cinoptions=>4,n-2,{2,^-2,:2,=2,g0,h2,p5,t0,+2,(0,u0,w1,m1
	setlocal shiftwidth=2
	setlocal softtabstop=2
	setlocal textwidth=79
	setlocal fo-=ro fo+=cql
endfunction

function s:GNUKeywords()
    syn keyword cOperator likely unlikely
    syn keyword cType u8 u16 u32 u64 s8 s16 s32 s64
    syn keyword cType __u8 __u16 __u32 __u64 __s8 __s16 __s32 __s64
endfunction

function s:GNUHighlighting()
    highlight default link GNUError ErrorMsg

    syn match GNUError / \+\ze\t/     " spaces before tab
    syn match GNUError /\%81v.\+/     " virtual column 81 and more

    " Highlight trailing whitespace, unless we're in insert mode and the
    " cursor's placed right after the whitespace. This prevents us from having
    " to put up with whitespace being highlighted in the middle of typing
    " something
    autocmd InsertEnter * match GNUError /\s\+\%#\@<!$/
    autocmd InsertLeave * match GNUError /\s\+$/
endfunction

" vim: ts=4 et sw=4
