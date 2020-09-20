if exists("g:loaded_clangsty")
    finish
endif
let g:loaded_clangsty = 1

augroup clangsty
    autocmd!

    autocmd FileType c,cpp call ClangFormatConfigure()
augroup END

function ClangFormatConfigure()
    let  apply_clangformat = 0

    if exists("g:clangsty_patterns")
        let path = expand('%:p')
	for p in g:clangsty_patterns
	    if path =~ p
	       let apply_clangformat = 1
	       break
	    endif
	endfor
    endif

    if apply_clangformat == 0
	return
    endif

    " Search for clang format file
    let cnt = 10
    let clangformatfilepath = expand('%:p:h') . "/"
    while cnt > 0
	let clangformatfile  = clangformatfilepath . ".clang-format"
	if filereadable(clangformatfile)
		break
	endif
	let clangformatfilepath = clangformatfilepath . "../"
	let cnt = cnt - 1
    endwhile

    let clangoptdict = {}
    if filereadable(clangformatfile)
	" echo "Processing clang formatfile: " clangformatfile
	for line in readfile(clangformatfile)
		if line =~ ':'
			let opt = split(line, ':')
			if len(opt) == 2
				let clangoptdict[opt[0]] = opt[1]
				"echo "Added clang opt " opt[0] ":" clangoptdict[opt[0]]
			endif
		endif
	endfor
    endif

    "autocmd BufWritePre <buffer> call Formatonsave()
    if has_key(clangoptdict, "ColumnLimit")
	" echo "Changing text width from " &l:textwidth " to " str2nr(clangoptdict["ColumnLimit"])
	let &l:textwidth = str2nr(clangoptdict["ColumnLimit"])
    endif
endfunction

" Clang autoformat
let g:clang_format_fallback_style = "none"
function! Formatonsave()
    "echo "!!!Called format save"
    let file = @%
    if filereadable(file)
        let l:formatdiff = 1
    endif
    py3f /home/build/bin/clang-format.py
endfunction

"autocmd BufWritePre *.c,*.h,*.cc,*.cpp call Formatonsave()

map <C-K> :py3f /home/build/bin/clang-format.py<CR>
imap <C-K> <c-o>:py3f /home/build/bin/clang-format.py<cr>
