.data
	g_proc dq ?
	g_p dq ?
.code
_Proc PROC
;...callback
_Proc ENDP
_Protection2 proc
	push rcx
	mov g_proc, rcx
	mov rcx, 176h	; Disabled
	rdmsr			; RAX:RDX=0x00000000
	mov g_p, rdx
	mov rax, _Proc
	wrmsr
	add esp, 4
	ret
_Protection2 endp
DisableWrite proc
	mov rax, cr0
	or  rax, 10000h
	mov cr0, rax
	sti
	ret
DisableWrite endp
EnableWrite proc
	cli
    mov rax,cr0
    and rax,not 10000h
    mov cr0,rax
	ret
EnableWrite endp
end