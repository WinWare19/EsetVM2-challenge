.CODE 
	RotateLeft PROC
		mov al, cl
		mov cl, dl
		rol al, cl
		ret
	RotateLeft ENDP

	RotateRight PROC
		mov al, cl
		mov cl, dl
		ror al, cl
		ret
	RotateRight ENDP

END