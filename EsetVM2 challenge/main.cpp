#include <Windows.h>
#include <iostream>
#include <winternl.h>
#include <vector>
#include <queue>
#include <stack>
#include <initializer_list>
#include <unordered_map>
using namespace std;

// =================================================

HANDLE default_heap = GetProcessHeap();

// =================================================

#define ERROR_EVM_INVALID_FILE_FORAMAT 0xE0000001

#define ESETVM2_SIGNATURE "ESET-VM2"
#define EVM_MAXIMUM_PROCESSORS_COUNT 0x40
#define EVM_INVALID_PROCESSOR_ID 0xFFFFFFFF
#define EVM_INVALID_RVA 0xFFFFFFFF
#define EVM_DEFAULT_STACK_SIZE 256
#define PAGE_SIZE 0x1000
#define EVM_INVALID_INSTRUCTION 0xFFFFFFFFFFFFFFFF
#define EVM_DEFAULT_THREAD_QUANTUM 0x2

// =================================================

typedef struct _EVM_FILE_HEADER {
	CHAR signature[0x8];
	DWORD dwCodeSize, dwDataSize, dwInitialDataSize;
} EVM_FILE_HEADER, *PEVM_FILE_HEADER, *LPEVM_FILE_HEADER;
typedef struct _NODE {
	_NODE* prev, * next;
} NODE, * PNODE, * LPNODE;

// =================================================

// extern functios ( implmented in helper.asm )
EXTERN_C BYTE RotateLeft(BYTE value, BYTE rotate_by);
EXTERN_C BYTE RotateRight(BYTE value, BYTE rotate_by);

// Memory helpers
BOOLEAN __stdcall IsBadBytePointer(LPBYTE);
BOOLEAN __stdcall IsBadRange(LPBYTE, SIZE_T);
void __stdcall SafeMemCopy(LPBYTE, LPBYTE, SIZE_T);
BOOLEAN __stdcall SafeMemCompare(LPBYTE, LPBYTE, SIZE_T);

// .evm file helpers
BOOLEAN __stdcall IsEvmFileValid(LPSTR, LPEVM_FILE_HEADER);

// =================================================

DWORD execution_context_tls_indx = TLS_OUT_OF_INDEXES;// used to store per processor execution context.

// =================================================

class DoublyLinkedList {
private:
	NODE head;
	INT dwItemsCount;

public:
	DoublyLinkedList() {
		head.prev = &head;
		head.next = &head;

		dwItemsCount = 0x0;
	}

	void __stdcall InsertHead(LPNODE new_node) {
		if (IsBadBytePointer((LPBYTE)new_node)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return;
		}
		new_node->next = head.next;
		new_node->prev = &head;
		head.next->prev = new_node;
		head.next = new_node;
		dwItemsCount++;
	}
	void __stdcall InsertTail(LPNODE new_node) {
		if (IsBadBytePointer((LPBYTE)new_node)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return;
		}
		new_node->prev = head.prev;
		new_node->next = &head;
		head.prev->next = new_node;
		head.prev = new_node;
		dwItemsCount++;
	}
	void __stdcall RemoveNode(LPNODE node) {
		if (IsBadBytePointer((LPBYTE)node) || node == &head || IsBadBytePointer((LPBYTE)node->next) || 
			IsBadBytePointer((LPBYTE)node->prev)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return;
		}
		node->prev->next = node->next;
		node->next->prev = node->prev;
		node->next = node->prev = NULL;
		dwItemsCount--;
	}
	ULONG __stdcall size() {
		ULONG count = dwItemsCount;
		return count;
	}

	LPNODE __stdcall begin() {
		LPNODE start = head.next;
		return start;
	}
	LPNODE __stdcall end() {
		return &head;
	}

};
template <typename T> class StackEx {
private:
	stack<T> items;
	CRITICAL_SECTION lock;
public:
	StackEx() {
		InitializeCriticalSection(&lock);
		items = stack<T>();
	}
	~StackEx() {
		DeleteCriticalSection(&lock);
	}

	T __stdcall pop() {
		T old_front = NULL;
		EnterCriticalSection(&lock);
		if (!items.empty()) {
			old_front = items.top();
			items.pop();
		}
		else SetLastError(ERROR_NO_MORE_ITEMS); // fail the pop operation if the queue is empty.
		LeaveCriticalSection(&lock);
		return old_front;
	}
	void __stdcall push(T item) {
		EnterCriticalSection(&lock);
		items.push(item); // set the front pointer to the new node if the queue was empty before the push operation.
		LeaveCriticalSection(&lock);
	}
	BOOLEAN __stdcall empty() {
		EnterCriticalSection(&lock);
		BOOL bIsEmpty = items.empty();
		LeaveCriticalSection(&lock);
		return bIsEmpty;
	}
};
template <typename T> class QueueEx {
private:
	queue<T> items;
	CRITICAL_SECTION lock;
public:
	QueueEx() {
		InitializeCriticalSection(&lock);
		items = queue<T>();
	}
	~QueueEx() {
		DeleteCriticalSection(&lock);
	}

	T __stdcall pop() {
		T old_front = NULL;
		EnterCriticalSection(&lock);
		if (!items.empty()) {
			old_front = items.front();
			items.pop();
		}
		else SetLastError(ERROR_NO_MORE_ITEMS); // fail the pop operation if the queue is empty.
		LeaveCriticalSection(&lock);
		return old_front;
	}
	void __stdcall push(T item) {
		EnterCriticalSection(&lock);
		items.push(item); // set the front pointer to the new node if the queue was empty before the push operation.
		LeaveCriticalSection(&lock);
	}
	BOOLEAN __stdcall empty() {
		EnterCriticalSection(&lock);
		BOOL bIsEmpty = items.empty();
		LeaveCriticalSection(&lock);
		return bIsEmpty;
	}
};

class EsetVM2 {
private:
	typedef enum _EVM_THREAD_STATE {
		EVM_THREAD_READY,
		EVM_THREAD_RUNNING,
		EVM_THREAD_WAITING,
		EVM_THREAD_TERMINATED
	} EVM_THREAD_STATE, * PEVM_THREAD_STATE, * LPEVM_THREAD_STATE;
	typedef struct _EVM_CONTEXT {
		INT64 r[0x10];
	} EVM_CONTEXT, * PEVM_CONTEXT, * LPEVM_CONTEXT;
	typedef struct _EVM_THREAD {
		CHAR signature[0x8];
		BOOLEAN bIsMainThread;
		ULONG dwAffinityMask; // processors where the thread is allowed to run
		EVM_CONTEXT context;
		UINT ip; // thread instruction pointer ( current bit in code bit stream )
		DWORD dwThreadId;
		StackEx<DWORD32>* stack; // used by call and ret instructions.
		EVM_THREAD_STATE state;
		LPVOID lpCreatorProcess; // the process to which this thread belongs.
		QueueEx<_EVM_THREAD*>* WaiterThreads; // used by the joinThread instruction.
		INT64 wait_timeout; // used to track the wait state entered by the sleep instruction.
		INT64 quantum; // number of instructions to execute before swicthing to another thread, used to run ready threads preemptively.
	} EVM_THREAD, * PEVM_THREAD, * LPEVM_THREAD;
	typedef struct _EVM_EXECUTION_CONTEXT {
		EsetVM2* vm;
		LPEVM_CONTEXT registers;
		LPEVM_THREAD current_thread;
		UINT current_processor;
	} EVM_EXECUTION_CONTEXT, *PEVM_EXECUTION_CONTEXT, *LPEVM_EXECUTION_CONTEXT;
	typedef struct _EVM_LOCK {
		CRITICAL_SECTION sync_lock; // protect the lock fron simultaneous access by multi evm processors.
		LPEVM_THREAD owner;
		LONG ref_count; // used tp track recursive acquisition by the same evm thread.
		QueueEx<LPEVM_THREAD>* waiters; // waiter threads;
	} EVM_LOCK, *PEVM_LOCK, *LPEVM_LOCK;

	class EsetVM2ExecutionUnit {
	private:
		typedef enum _EVM_OPERAND_TYPE {
			EvmConstantOperand,
			EvmCodeAddressOperand,
			EvmDataAccessOperand,
			EvmInvalidOperand // indicates either an invalid or a non existing operand ( used for definig instructions that have less than 3 operands ).
		} EVM_OPERAND_TYPE, * PEVM_OPERAND_TYPE, * LPEVM_OPERAND_TYPE;
		typedef struct _EVM_OPERAND {
		public:
			_EVM_OPERAND(EVM_OPERAND_TYPE type, DWORD64 const_val, DWORD32 code_offset, BYTE mem_access_modifier, BYTE r) {
				this->type = type;
				switch (this->type) {
					case EvmConstantOperand: this->const_val = const_val; break;
					case EvmCodeAddressOperand: this->code_offset = code_offset; break;
					case EvmDataAccessOperand: {
						this->r = r;
						this->mem_access_modifier = mem_access_modifier;
					} break;
				}
			}
			EVM_OPERAND_TYPE type;
			union {
				INT64 const_val;
				DWORD32 code_offset;
				struct {
					BYTE mem_access_modifier; // byte, word, dword and qword modifiers.
					BYTE r; // register index;
				};
			};
		} EVM_OPERAND, *PEVM_OPERAND, *LPEVM_OPERAND;
		typedef void(__stdcall*ExeProc)(LPEVM_EXECUTION_CONTEXT, vector<EVM_OPERAND>);
		typedef enum _INSTRUCTION_OPCODE_MASK {
			mov = 0x0,
			loadConst = 0x20,
			add = 0x44,
			sub = 0x48,
			mul = 0x54,
			div = 0x4c,
			mod = 0x50,
			compare = 0x60,
			jump = 0x68,
			jumpEqual = 0x70,
			read = 0x80,
			write = 0x88,
			consoleRead = 0x90,
			consoleWrite = 0x98,
			createThread = 0xa0,
			joinThread = 0xa8,
			hlt = 0xb0,
			sleep = 0xb8,
			call = 0xC0,
			ret = 0xD0,
			lock = 0xE0,
			unlock = 0xF0
		} INSTRUCTION_OPCODE_MASK, * PINSTRUCTION_OPCODE_MASK, * LPINSTRUCTION_OPCODE_MASK;
		typedef struct _EVM_INSTRUCTION {
		public:
			NODE InstructionSetEntry; // used to link the instruction in the instruction set list.
			INSTRUCTION_OPCODE_MASK opcode_mask; // maximum opcode size is 6 bits.
			BYTE operands_count; // maxumu of 4 operands per instruction.
			BYTE opcode_length; // the opcode length in bits.
			EVM_OPERAND_TYPE* operand_definitions;
			LPSTR name;
			ExeProc exe_proc;
			_EVM_INSTRUCTION(LPCSTR name, LPVOID exe_proc, INSTRUCTION_OPCODE_MASK opcode_mask, BYTE opcode_length, BYTE operands_count, 
				initializer_list<EVM_OPERAND_TYPE> operand_definitions) {
				
				this->exe_proc = static_cast<ExeProc>(exe_proc);
				this->name = (LPSTR)name;
				this->opcode_mask = opcode_mask;
				this->opcode_length = opcode_length;
				this->operands_count = min(operands_count, operand_definitions.size());
				this->operand_definitions = (EVM_OPERAND_TYPE*)HeapAlloc(default_heap, HEAP_ZERO_MEMORY,
					sizeof(EVM_OPERAND_TYPE) * operands_count);
				if (!IsBadBytePointer((LPBYTE)this->operand_definitions)) {
					UINT index = 0;
					for (EVM_OPERAND_TYPE operand_type : operand_definitions) {
						this->operand_definitions[index++] = operand_type;
					}
				}
				else this->operand_definitions = NULL;
			}
		} EVM_INSTRUCTION, * PEVM_INSTRUCTION, * LPEVM_INSTRUCTION;

		static void __stdcall __mov(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x2 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand) return;

			INT64 src = 0x0; 
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&src, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else src = registers->r[operands[0].r];

			ULONG_PTR dest = operands[1].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[1].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r];

			if (operands[1].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest,  0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&src, operands[1].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[1].mem_access_modifier));
		}
		static void __stdcall __loadConst(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x2 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if(operands[0].type != EvmConstantOperand || operands[1].type != EvmDataAccessOperand) return;

			DWORD64 const_val = operands[0].const_val;
			ULONG_PTR dest =  operands[1].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[1].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase +  registers->r[operands[1].r];
			
			if (operands[1].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest, 0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&const_val, operands[1].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[1].mem_access_modifier)); 
		}
		static void __stdcall __add(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand) 
				return;

			ULONG_PTR dest = operands[2].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[2].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			INT64 operand_0 = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_0, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else operand_0 = registers->r[operands[0].r];

			INT64 operand_1 = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_1, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else operand_1 = registers->r[operands[1].r];

			INT64 result = operand_0 + operand_1;

			if (operands[2].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest, 0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&result, operands[2].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[2].mem_access_modifier));
		}
		static void __stdcall __sub(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand)
				return;

			ULONG_PTR dest = operands[2].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[2].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			INT64 operand_0 = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_0, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else operand_0 = registers->r[operands[0].r];

			INT64 operand_1 = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_1, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else operand_1 = registers->r[operands[1].r];

			INT64 result = operand_0 - operand_1;

			if (operands[2].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest, 0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&result, operands[2].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[2].mem_access_modifier));
		}
		static void __stdcall __mul(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand)
				return;

			ULONG_PTR dest = operands[2].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[2].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			INT64 operand_0 = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_0, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else operand_0 = registers->r[operands[0].r];

			INT64 operand_1 = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_1, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else operand_1 = registers->r[operands[1].r];

			INT64 result = operand_0 * operand_1;

			if (operands[2].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest, 0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&result, operands[2].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[2].mem_access_modifier));
 		}
		static void __stdcall __div(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand)
				return;

			INT64 operand_1 = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_1, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else operand_1 = registers->r[operands[1].r];
			
			if (operand_1 == 0x0) {
				printf_s("EXCEPTION!! a devision by zero is not allowed.\n");
				InterlockedExchange((LONG*)&thread->state, EVM_THREAD_TERMINATED);
				return;
			}

			ULONG_PTR dest = operands[2].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[2].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			INT64 operand_0 = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_0, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else operand_0 = registers->r[operands[0].r];

			INT64 result = operand_0 / operand_1;

			if (operands[2].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest, 0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&result, operands[2].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[2].mem_access_modifier));
		}
		static void __stdcall __mod(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand)
				return;

			ULONG_PTR dest = operands[2].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[2].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			INT64 operand_0 = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_0, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else operand_0 = registers->r[operands[0].r];

			INT64 operand_1 = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_1, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else operand_1 = registers->r[operands[1].r];

			INT64 result = operand_0 % operand_1;

			if (operands[2].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest, 0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&result, operands[2].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[2].mem_access_modifier));
		}
		static void __stdcall __compare(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand)
				return;

			ULONG_PTR dest = operands[2].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[2].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			INT64 operand_0 = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_0, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else operand_0 = registers->r[operands[0].r];

			INT64 operand_1 = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_1, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else operand_1 = registers->r[operands[1].r];

			INT64 result = operand_0 < operand_1 ? -1 : (operand_0 == operand_1 ? 0x0 : 0x1);

			if (operands[2].mem_access_modifier == 0xFF) ZeroMemory((LPBYTE)dest, 0x8);
			SafeMemCopy((LPBYTE)dest, (LPBYTE)&result, operands[2].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[2].mem_access_modifier));
		}
		static void __stdcall __jump(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD)) return;

			if (operands[0].type != EvmCodeAddressOperand) return;

			thread->ip = operands[0].code_offset;
		}
		static void __stdcall __jumpEqual(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmCodeAddressOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand)
				return;

			INT64 operand_0 = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_0, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else operand_0 = registers->r[operands[1].r];

			INT64 operand_1 = 0x0;
			if (operands[2].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand_1, execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r],
				pow(2, operands[2].mem_access_modifier));
			else operand_1 = registers->r[operands[2].r];

			if(operand_0 == operand_1) thread->ip = operands[0].code_offset;
		}
		static void __stdcall __read(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (execution_context->vm->argc < 0x1) return;

			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x4 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;
			LPEVM_PROCESS process = (LPEVM_PROCESS)execution_context->current_thread->lpCreatorProcess;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) || IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT) || 
				IsBadRange((LPBYTE)process, sizeof EVM_PROCESS)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand ||
				operands[3].type != EvmDataAccessOperand)
				return;

			DWORD64 offset = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&offset, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else offset = registers->r[operands[0].r];

			DWORD64 bytes_count = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&bytes_count, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else bytes_count = registers->r[operands[1].r];

			LPBYTE buffer = 0x0;
			if (operands[2].mem_access_modifier != 0xFF) buffer = (LPBYTE)&registers->r[operands[2].r];
			else buffer = execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			DWORD* read_bytes = 0x0;
			if (operands[3].mem_access_modifier != 0xFF) read_bytes = (DWORD*)registers->r[operands[3].r];
			else read_bytes = (DWORD*)&registers->r[operands[3].r];

			HANDLE file_handle = CreateFileA(execution_context->vm->argv[0x0], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, NULL);
			if (file_handle == INVALID_HANDLE_VALUE) return;

			SetFilePointer(file_handle, offset, 0x0, FILE_BEGIN);
			ReadFile(file_handle, buffer, bytes_count, read_bytes, NULL);

			CloseHandle(file_handle);
		}
		static void __stdcall __write(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (execution_context->vm->argc < 0x1) return;

			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x3 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;
			LPEVM_PROCESS process = (LPEVM_PROCESS)execution_context->current_thread->lpCreatorProcess;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) || IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT) ||
				IsBadRange((LPBYTE)process, sizeof EVM_PROCESS)) return;

			if (operands[0].type != EvmDataAccessOperand || operands[1].type != EvmDataAccessOperand || operands[2].type != EvmDataAccessOperand)
				return;

			DWORD64 offset = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&offset, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else offset = registers->r[operands[0].r];

			DWORD64 bytes_count = 0x0;
			if (operands[1].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&bytes_count, execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r],
				pow(2, operands[1].mem_access_modifier));
			else bytes_count = registers->r[operands[1].r];

			LPBYTE buffer = 0x0;
			if (operands[2].mem_access_modifier != 0xFF) buffer = (LPBYTE)&registers->r[operands[2].r];
			else buffer = execution_context->vm->lpVmMemoryBase + registers->r[operands[2].r];

			HANDLE file_handle = CreateFileA(execution_context->vm->argv[0x0], GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL | FILE_FLAG_RANDOM_ACCESS, NULL);
			if (file_handle == INVALID_HANDLE_VALUE) return;
			
			SetFilePointer(file_handle, offset, 0x0, FILE_BEGIN);
			WriteFile(file_handle, buffer, bytes_count, 0x0, NULL);

			CloseHandle(file_handle);
		}
		static void __stdcall __consoleRead(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand) return;

			ULONG_PTR dest = operands[0].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[0].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r];

			printf_s(">>> ");

			scanf_s("%d", (LPBYTE)dest, operands[0].mem_access_modifier == 0xFF ? 0x8 : pow(2, operands[0].mem_access_modifier));
		}
		static void __stdcall __consoleWrite(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand) return;

			INT64 operand = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&operand, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else operand = registers->r[operands[0].r];

			printf_s("0x%llX\n", operand);
		}
		static void __stdcall __createThread(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x2 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;
			LPEVM_PROCESS process = (LPEVM_PROCESS)thread->lpCreatorProcess;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) || IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT) || 
				IsBadRange((LPBYTE)process, sizeof EVM_PROCESS)) return;

			if (operands[0].type != EvmCodeAddressOperand || operands[1].type != EvmDataAccessOperand) return;

			DWORD32 entry_point = operands[0].code_offset;

			ULONG_PTR out_thread_id = operands[1].mem_access_modifier == 0xFF ? (ULONG_PTR)&registers->r[operands[1].r] :
				(ULONG_PTR)execution_context->vm->lpVmMemoryBase + registers->r[operands[1].r];

			LPEVM_THREAD new_thread = execution_context->vm->CreateEvmThread(process, registers, entry_point, 0x0);
			if (!IsBadRange((LPBYTE)new_thread, sizeof EVM_THREAD)) *(DWORD*)out_thread_id = new_thread->dwThreadId;
		}
		static void __stdcall __joinThread(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;
			LPEVM_PROCESS process = (LPEVM_PROCESS)thread->lpCreatorProcess;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) || IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT) || 
				IsBadRange((LPBYTE)process, sizeof EVM_PROCESS)) return;

			if (operands[0].type != EvmDataAccessOperand) return;

			DWORD64 thread_id = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&thread_id, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else thread_id = registers->r[operands[0].r];

			if (thread_id != thread->dwThreadId) {
				LPEVM_THREAD target_thread = NULL;
				if (process->threads->find(thread_id) != process->threads->end()) target_thread = process->threads->at(thread_id);
				
				if (!IsBadRange((LPBYTE)target_thread, sizeof EVM_THREAD) && SafeMemCompare((LPBYTE)target_thread->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8) && 
					target_thread->state != EVM_THREAD_TERMINATED) {
					InterlockedExchange((LONG*)&thread->state, EVM_THREAD_WAITING);
					target_thread->WaiterThreads->push(thread);
				}
			}
		}
		static void __stdcall __hlt(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size())
				return;

			LPEVM_THREAD thread = execution_context->current_thread;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD)) return;

			InterlockedExchange((LONG*)&thread->state, EVM_THREAD_TERMINATED);

			// unwait threads that have called joinThread to wait for this one to complete. 
			while (!thread->WaiterThreads->empty()) {
				LPEVM_THREAD waiter = thread->WaiterThreads->pop();
				if (!IsBadRange((LPBYTE)waiter, sizeof EVM_THREAD) && SafeMemCompare((LPBYTE)thread->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8)) {
					InterlockedExchange((LONG*)&waiter->state, EVM_THREAD_READY);
					execution_context->vm->QueueThreadForExecution(waiter);
				}
			}

			if (thread->bIsMainThread) {
				LPEVM_PROCESS process = (LPEVM_PROCESS)thread->lpCreatorProcess;
				if (IsBadRange((LPBYTE)process, sizeof _EVM_PROCESS) || 
					IsBadRange((LPBYTE)process->threads, sizeof unordered_map<DWORD32, LPEVM_THREAD>)) return;

				for (pair<DWORD32, LPEVM_THREAD> item : *process->threads) {
					if (!IsBadRange((LPBYTE)item.second, sizeof EVM_THREAD) && item.second->lpCreatorProcess == (LPVOID)process) 
						InterlockedExchange((LONG*)&item.second->state, EVM_THREAD_TERMINATED);
				}
			}
		}
		static void __stdcall __sleep(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand) return;

			INT64 timeout = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&timeout, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else timeout = registers->r[operands[0].r];

			if (timeout > 0x0) {
				thread->wait_timeout = timeout;
				InterlockedExchange((LONG*)&thread->state, EVM_THREAD_WAITING);
				
				// queue the thread to  the sleep queue.
				execution_context->vm->processors[execution_context->current_processor]->sleep_queue->push(thread);
			}
		}
		static void __stdcall __call(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD)) return;

			if (operands[0].type != EvmCodeAddressOperand) return;
			
			thread->stack->push(thread->ip);

			thread->ip = operands[0].code_offset;
		}
		static void __stdcall __ret(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size())
				return;

			LPEVM_THREAD thread = execution_context->current_thread;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD)) return;

			DWORD32 ip = thread->stack->pop();

			thread->ip = ip;
		}
		static void __stdcall __lock(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1 || !execution_context->vm->lpVmMemoryBase)
				return;

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand) return;

			DWORD64 lock_id = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&lock_id, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else lock_id = registers->r[operands[0].r];

			LPEVM_LOCK lock = NULL;

			if (execution_context->vm->locks.find(lock_id) == execution_context->vm->locks.end()) {
				lock = (LPEVM_LOCK)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, sizeof EVM_LOCK);
				if (lock) {
					InitializeCriticalSection(&lock->sync_lock);
					lock->waiters = new QueueEx<LPEVM_THREAD>();
				}
			}
			else lock = execution_context->vm->locks[lock_id];

			if (lock) {
				EnterCriticalSection(&lock->sync_lock);
				if (lock->owner == thread) InterlockedIncrement(&lock->ref_count);
				else {
					if (!lock->owner) {
						lock->owner = thread;
						lock->ref_count = 0x1;
					}
					else {
						InterlockedExchange((LONG*)&thread->state, EVM_THREAD_WAITING);
						lock->waiters->push(thread);
					}
				}
				execution_context->vm->locks[lock_id] = lock;
				LeaveCriticalSection(&lock->sync_lock);
			}
		}
		static void __stdcall __unlock(LPEVM_EXECUTION_CONTEXT execution_context, vector<EVM_OPERAND> operands) {
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT) || operands.size() != 0x1 || !execution_context->vm->lpVmMemoryBase)
				return;
			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_CONTEXT registers = execution_context->registers;

			if (IsBadRange((LPBYTE)thread, sizeof _EVM_THREAD) ||
				IsBadRange((LPBYTE)registers, sizeof _EVM_CONTEXT)) return;

			if (operands[0].type != EvmDataAccessOperand) return;

			DWORD64 lock_id = 0x0;
			if (operands[0].mem_access_modifier != 0xFF) SafeMemCopy((LPBYTE)&lock_id, execution_context->vm->lpVmMemoryBase + registers->r[operands[0].r],
				pow(2, operands[0].mem_access_modifier));
			else lock_id = registers->r[operands[0].r];

			LPEVM_LOCK lock = NULL;

			if (execution_context->vm->locks.find(lock_id) != execution_context->vm->locks.end()) {
				lock = execution_context->vm->locks[lock_id];
				if (lock && lock->owner == thread) {
					EnterCriticalSection(&lock->sync_lock);
					InterlockedDecrement(&lock->ref_count);
					if (!lock->ref_count) {
						if (!lock->waiters->empty()) {
							// the wait list is not empty
							LPEVM_THREAD waiter = lock->waiters->pop();
							if (!IsBadRange((LPBYTE)waiter, sizeof EVM_THREAD) && SafeMemCompare((LPBYTE)waiter->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8)) {
								lock->owner = waiter;
								lock->ref_count = 0x1;
								InterlockedExchange((LONG*)&waiter->state, EVM_THREAD_READY);
								execution_context->vm->QueueThreadForExecution(waiter);
							}
						}
						else {
							lock->owner = NULL; // the lock is free
							lock->ref_count = 0x0;
						}
					}
					execution_context->vm->locks[lock_id] = lock;
					LeaveCriticalSection(&lock->sync_lock);
				}
			}
		}

		DWORD64 __stdcall ReadBitsFromLeftToRight(BYTE* bit_stream, UINT bit_index, INT64 bits_count) {
			SIZE_T bit_iterator[0x2] = { 0x0, bit_index };
			INT64 byte_iterator[0x2] = { bits_count / 0x8 + (bits_count % 8 == 0x0 ? 0x0 : 0x1) - 0x1, bit_index / 0x8 };

			DWORD64 result = 0x0;
			INT64 shift_amount = (byte_iterator[0x0] + 0x1) * 0x8 - bits_count;

			while (bit_iterator[0x0] < bits_count) {
				BYTE mask = (1 << (0x7 - (bit_iterator[0x1] % 0x8)));

				*(BYTE*)((UINT_PTR)&result + byte_iterator[0x0]) |= RotateLeft((bit_stream[byte_iterator[0x1]] & mask), bit_index);

				bit_iterator[0x0]++;
				bit_iterator[0x1]++;

				if (bit_iterator[0x0] % 8 == 0x0) byte_iterator[0x0]--;
				if (bit_iterator[0x1] % 8 == 0x0) byte_iterator[0x1]++;
			}

			return result >> shift_amount;
		}
		DWORD64 __stdcall ReadBitsFromRightToLeft(BYTE* bit_stream, UINT bit_index, INT64 bits_count) {
			SIZE_T bit_iterator[0x2] = { 0x0, bit_index + bits_count - 0x1 };
			INT64 byte_iterator[0x2] = { bits_count / 0x8 + (bits_count % 8 == 0x0 ? 0x0 : 0x1) - 0x1,
				(bit_index + bits_count) / 0x8 + ((bit_index + bits_count) % 8 == 0x0 ? 0x0 : 0x1) - 0x1 };

			DWORD64 result = 0x0;
			INT64 shift_amount = (byte_iterator[0x0] + 0x1) * 0x8 - bits_count;

			while (bit_iterator[0x0] < bits_count) {
				BYTE mask = (1 << (0x7 - bit_iterator[0x1] % 0x8));

				*(BYTE*)((UINT_PTR)&result + byte_iterator[0x0]) |= RotateRight(RotateLeft(bit_stream[byte_iterator[0x1]] & mask,
					(bit_iterator[0x1] % bits_count - (bits_count - 0x1 - bit_iterator[0x1] % bits_count))), bit_index);


				bit_iterator[0x0]++;
				if (bit_iterator[0x0] % 8 == 0x0) byte_iterator[0x0]--;

				if (bit_iterator[0x1] % 8 == 0x0) byte_iterator[0x1]--;
				bit_iterator[0x1]--;
			}

			return result >> shift_amount;
		}

		DoublyLinkedList* instruction_set; // all valid instructions.

	public:
		EsetVM2ExecutionUnit() {
			// initialize the instrucion set.
			instruction_set = new DoublyLinkedList();
			if (IsBadRange((LPBYTE)instruction_set, sizeof DoublyLinkedList)) return;

			// mov arg1, arg2 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("mov", __mov, mov, 0x3, 0x2, {EvmDataAccessOperand, EvmDataAccessOperand}))->InstructionSetEntry);
			// loadConst constant, arg1
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("loadConst", __loadConst, loadConst, 0x3, 0x2, { EvmConstantOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// add arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("add", __add, add, 0x6, 0x3, { EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// sub arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("sub", __sub, sub, 0x6, 0x3, { EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// mul arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("mul", __mul, mul, 0x6, 0x3, {EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand}))->InstructionSetEntry);
			// div arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("div", __div, div, 0x6, 0x3, { EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// mod arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("mod", __mod, mod, 0x6, 0x3, { EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// compare arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("compare", __compare, compare, 0x5, 0x3, { EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// jump address
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("jump", __jump, jump, 0x5, 0x1, { EvmCodeAddressOperand }))->InstructionSetEntry);
			// jumpEqual arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("jumpEqual", __jumpEqual, jumpEqual, 0x5, 0x3, { EvmCodeAddressOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// read arg1, arg2, arg3, arg4 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("read", __read, read, 0x5, 0x4, { EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// write arg1, arg2, arg3 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("write", __write, write, 0x5, 0x3, { EvmDataAccessOperand, EvmDataAccessOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// consoleRead arg1 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("consoleRead", __consoleRead, consoleRead, 0x5, 0x1, { EvmDataAccessOperand }))->InstructionSetEntry);
			// consoleWrite arg1 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("consoleWrite", __consoleWrite, consoleWrite, 0x5, 0x1, { EvmDataAccessOperand }))->InstructionSetEntry);
			// createThread address, arg1 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("createThread", __createThread, createThread, 0x5, 0x2, { EvmCodeAddressOperand, EvmDataAccessOperand }))->InstructionSetEntry);
			// joinThread arg1 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("joinThread", __joinThread, joinThread, 0x5, 0x1, { EvmDataAccessOperand }))->InstructionSetEntry);
			// hlt
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("hlt", __hlt, hlt, 0x5, 0x0, {}))->InstructionSetEntry);
			// sleep arg1 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("sleep", __sleep, sleep, 0x5, 0x1, { EvmDataAccessOperand }))->InstructionSetEntry);
			// call address 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("call", __call, call, 0x4, 0x1, { EvmCodeAddressOperand }))->InstructionSetEntry);
			// ret
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("ret", __ret, ret, 0x4, 0x0, {}))->InstructionSetEntry);
			// lock arg1 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("lock", __lock, lock, 0x4, 0x1, { EvmDataAccessOperand }))->InstructionSetEntry);
			// unlock arg1 
			instruction_set->InsertTail(&(new _EVM_INSTRUCTION("unlock", __unlock, unlock, 0x4, 0x1, { EvmDataAccessOperand }))->InstructionSetEntry);
		}
		~EsetVM2ExecutionUnit() {
			if (!IsBadBytePointer((LPBYTE)instruction_set)) {
				for (LPNODE it = instruction_set->begin(); !IsBadBytePointer((LPBYTE)it) && it != instruction_set->end(); it = it->next) {
					LPEVM_INSTRUCTION instruction = CONTAINING_RECORD(it, EVM_INSTRUCTION, InstructionSetEntry);
					if (!IsBadRange((LPBYTE)instruction, sizeof EVM_INSTRUCTION)) delete instruction;
				}
				delete instruction_set;
			}
		}

		BOOLEAN __stdcall Execute(LPBYTE bit_stream) {
			if (IsBadBytePointer(bit_stream)) {
				SetLastError(ERROR_INVALID_PARAMETER);
				return FALSE;
			}

			LPEVM_EXECUTION_CONTEXT execution_context = (LPEVM_EXECUTION_CONTEXT)TlsGetValue(execution_context_tls_indx);
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT)) {
				SetLastError(ERROR_INVALID_CONFIG_VALUE);
				return FALSE;
			}

			LPEVM_THREAD thread = execution_context->current_thread;
			LPEVM_PROCESS process_info = (LPEVM_PROCESS)thread->lpCreatorProcess;

			vector<EVM_OPERAND> operands; // used to hold instruction operands during execution.

			INT64 quantum = thread->quantum;

			do {
				operands.clear();

				LPEVM_INSTRUCTION instruction = NULL;
				BOOLEAN b_valid = FALSE;

				// find the right instruction by backward iterating the instruction set.
				for (LPNODE it = instruction_set->end()->prev; !IsBadBytePointer((LPBYTE)it) && it != instruction_set->end(); it = it->prev) {
					instruction = CONTAINING_RECORD(it, EVM_INSTRUCTION, InstructionSetEntry);
					if (!IsBadRange((LPBYTE)instruction, sizeof EVM_INSTRUCTION) &&
						ReadBitsFromLeftToRight(bit_stream, thread->ip, instruction->opcode_length) ==
						(instruction->opcode_mask >> (0x8 - instruction->opcode_length))) {
						
						b_valid = TRUE;
						break;
					}
				}
				if (!b_valid) {
					SetLastError(ERROR_UNHANDLED_EXCEPTION);
					return FALSE;
				}

				// the instruction is valid.
				thread->ip += instruction->opcode_length;

				if (instruction->operands_count) {
					for (UINT i = 0x0; i < instruction->operands_count; i++) {
						INT64 const_val = 0x0;
						DWORD32 code_offset = 0x0;
						BYTE mem_access_modifier = 0xFF, r = 0x0;
						switch (instruction->operand_definitions[i]) {
							case EvmConstantOperand: {
								if ((thread->ip + 64) >= (process_info->loaded_module.code_size * 0x8)) goto BREAK;
								const_val = ReadBitsFromRightToLeft(bit_stream, thread->ip, 64);
								thread->ip += 64;

							} break;
							case EvmCodeAddressOperand: {
								if ((thread->ip + 32) >= (process_info->loaded_module.code_size * 0x8)) goto BREAK;
								code_offset = ReadBitsFromRightToLeft(bit_stream, thread->ip, 32);
								thread->ip += 32;
							} break;
							case EvmDataAccessOperand: {
								if (!ReadBitsFromLeftToRight(bit_stream, thread->ip, 0x1)) {
									if ((thread->ip + 0x5) >= (process_info->loaded_module.code_size * 0x8)) goto BREAK;
									r = ReadBitsFromRightToLeft(bit_stream, thread->ip + 0x1, 0x4);
									thread->ip += 0x5;
								}
								else {
									if ((thread->ip + 0x7) >= (process_info->loaded_module.code_size * 0x8)) goto BREAK;
									mem_access_modifier = ReadBitsFromLeftToRight(bit_stream, thread->ip + 0x1, 0x2);
									r = ReadBitsFromRightToLeft(bit_stream, thread->ip + 0x3, 0x4);
									thread->ip += 0x7;
								}
							} break;
						}
						operands.push_back(EVM_OPERAND(instruction->operand_definitions[i], const_val, code_offset, mem_access_modifier, r)); // insert the opernd in the operands list.
					}
				}
				
				goto CONTINUE;

			BREAK:
				break;

			CONTINUE:
				instruction->exe_proc(execution_context, operands); // execute the instruction.
				SafeMemCopy((LPBYTE)&thread->context, (LPBYTE)execution_context->registers, sizeof EVM_CONTEXT); // update the thread's own registers set with current values after execution.

				// decrement the thread's quantum
				quantum--;
			} while (thread->state == EVM_THREAD_RUNNING && thread->ip < (process_info->loaded_module.code_size * 0x8) && 
				quantum > 0x0);

			if (thread->state == EVM_THREAD_RUNNING && quantum <= 0x0) {
				InterlockedExchange((LONG*)&thread->state, EVM_THREAD_READY);
				execution_context->vm->QueueThreadForExecution(thread);
			}
			else if (thread->state == EVM_THREAD_TERMINATED) {
				delete thread->stack;
				delete thread->WaiterThreads;
				process_info->threads->erase(thread->dwThreadId);
				HeapFree(default_heap, 0x8, thread);
				if (thread->bIsMainThread) {
					printf_s("\n[ %s ] exited ...\n\nDiasm:\n------\n", execution_context->vm->evm_file_path);
					Diasm(process_info->loaded_module.evm_module_base, process_info->loaded_module.code_size);
				}
				HeapFree(default_heap, 0x8, process_info);
			}
		}
		BOOLEAN __stdcall Diasm(LPBYTE bit_stream, SIZE_T stream_size) {
			if (IsBadBytePointer(bit_stream) || stream_size <= 0x0) {
				SetLastError(ERROR_INVALID_PARAMETER);
				return FALSE;
			}

			LPEVM_EXECUTION_CONTEXT execution_context = (LPEVM_EXECUTION_CONTEXT)TlsGetValue(execution_context_tls_indx);
			if (IsBadRange((LPBYTE)execution_context, sizeof _EVM_EXECUTION_CONTEXT)) {
				SetLastError(ERROR_INVALID_CONFIG_VALUE);
				return FALSE;
			}

			vector<EVM_OPERAND> operands; // used to hold instruction operands during execution.
			DWORD64 ip = 0x0;

			do {
				operands.clear();

				LPEVM_INSTRUCTION instruction = NULL;
				BOOLEAN b_valid = FALSE;

				// find the right instruction by backward iterating the instruction set.
				for (LPNODE it = instruction_set->end()->prev; !IsBadBytePointer((LPBYTE)it) && it != instruction_set->end(); it = it->prev) {
					instruction = CONTAINING_RECORD(it, EVM_INSTRUCTION, InstructionSetEntry);
					if (!IsBadRange((LPBYTE)instruction, sizeof EVM_INSTRUCTION) &&
						ReadBitsFromLeftToRight(bit_stream, ip, instruction->opcode_length) ==
						(instruction->opcode_mask >> (0x8 - instruction->opcode_length))) {

						b_valid = TRUE;
						break;
					}
				}
				if (!b_valid) {
					SetLastError(ERROR_UNHANDLED_EXCEPTION);
					return FALSE;
				}

				// the instruction is valid.
				ip += instruction->opcode_length;

				if (instruction->operands_count) {
					for (UINT i = 0x0; i < instruction->operands_count; i++) {
						INT64 const_val = 0x0;
						DWORD32 code_offset = 0x0;
						BYTE mem_access_modifier = 0xFF, r = 0x0;
						switch (instruction->operand_definitions[i]) {
						case EvmConstantOperand: {
							if ((ip + 64) >= (stream_size * 0x8)) goto BREAK;
							const_val = ReadBitsFromRightToLeft(bit_stream, ip, 64);
							ip += 64;

						} break;
						case EvmCodeAddressOperand: {
							if ((ip + 32) >= (stream_size * 0x8)) goto BREAK;
							code_offset = ReadBitsFromRightToLeft(bit_stream, ip, 32);
							ip += 32;
						} break;
						case EvmDataAccessOperand: {
							if (!ReadBitsFromLeftToRight(bit_stream, ip, 0x1)) {
								if ((ip + 0x5) >= (stream_size * 0x8)) goto BREAK;
								r = ReadBitsFromRightToLeft(bit_stream, ip + 0x1, 0x4);
								ip += 0x5;
							}
							else {
								if ((ip + 0x7) >= (stream_size * 0x8)) goto BREAK;
								mem_access_modifier = ReadBitsFromLeftToRight(bit_stream, ip + 0x1, 0x2);
								r = ReadBitsFromRightToLeft(bit_stream, ip + 0x3, 0x4);
								ip += 0x7;
							}
						} break;
						}
						operands.push_back(EVM_OPERAND(instruction->operand_definitions[i], const_val, code_offset, mem_access_modifier, r)); // insert the opernd in the operands list.
					}
				}

				goto CONTINUE;

			BREAK:
				break;

			CONTINUE:
				printf_s("%s ", instruction->name);
				for (UINT i = 0x0; i < operands.size(); i++) {
					if (operands[i].type == EvmCodeAddressOperand)
						printf_s("0x%X%s", operands[i].code_offset, i == operands.size() - 0x1 ? "\n" : ", ");
					else if (operands[i].type == EvmConstantOperand)
						printf_s("0x%llX%s", operands[i].const_val, i == operands.size() - 0x1 ? "\n" : ", ");
					else if (operands[i].type == EvmDataAccessOperand) {
						if (operands[i].mem_access_modifier == 0xFF) {
							printf_s("r%d%s", operands[i].r, i == operands.size() - 0x1 ? "\n" : ", ");
						}
						else {
							LPCSTR modifiers[] = { "BYTE", "WORD", "DWORD", "QWORD" };
							printf_s("%s[r%d]%S", modifiers[operands[i].mem_access_modifier], operands[i].r, i == operands.size() - 0x1 ? "\n" : ", ");
						}
					}
				}

			} while (ip < (stream_size * 0x8));
		}
	};


	typedef struct _EVM_PROCESSOR {
		CHAR signature[0x8];
		EVM_CONTEXT registers;
		DWORD threads_count; // the number of threads currently queued to the processor.
		QueueEx<LPEVM_THREAD>* ready_queue; // ready threads to be executed on the processor
		QueueEx<LPEVM_THREAD>* sleep_queue; // threads currently in a sleep state entered by calling sleep.
		LPBYTE ip; // instruction pointer
		DWORD thread_id; // EsetVM2 processors are represented as seperatelly running real threads.
		BOOLEAN bIdle, bInitialized;
		DWORD processor_id; // the processor identifier (0, 1, 2, ...)
		HANDLE initialization_event; // an event that gets signaled when the processor starts.
		EsetVM2ExecutionUnit* lpExecutionUnit; // used to crack instructions on this processor. ( each evm processor has its own decoding unit ). 
	} EVM_PROCESSOR, * PEVM_PROCESSOR, * LPEVM_PROCESSOR;
	typedef struct _EVM_LOADED_MODULE {
		LPSTR module_path;
		LPBYTE evm_module_base; // the base address of the loaded .evm file in memory.
		ULONG code_rva; // the relative virtual address (offset) of the code section of the loaded .evm file in memory.
		ULONG data_rva; // the relative virtual address (offset) of the data section of the loaded .evm file in memory.
		SIZE_T image_size, code_size;
	} EVM_LOADED_MODULE, *PEVM_LOADED_MODULE, *LPEVM_LOADED_MODULE;
	typedef struct _EVM_PROCESS {
		unordered_map<DWORD32, LPEVM_THREAD>* threads; // the first theread in the list is the main thread of the process.
		EVM_LOADED_MODULE loaded_module; // information about the loaded .evm file in memory.
		NODE ProcessEntry; // used to link the process in the VM processes list.
	} EVM_PROCESS, * PEVM_PROCESS, * LPEVM_PROCESS;
	typedef struct _EVM_PROCESSOR_CONTEXT{
		EsetVM2* vm; // pointer to the EsetVM2 instance that the processor belongs to.
		LPEVM_PROCESSOR processor_info; // pointer to the processor info structure of the processor.
	} EVM_PROCESSOR_CONTEXT, * PEVM_PROCESSOR_CONTEXT, * LPEVM_PROCESSOR_CONTEXT;

	// =================================================

	static DWORD __stdcall EsetVM2ProcessorProc(_EVM_PROCESSOR_CONTEXT* processor_context) {
		if (IsBadBytePointer((LPBYTE)processor_context)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return EXIT_FAILURE;
		}

		if (!SafeMemCompare((LPBYTE)processor_context->processor_info->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8)) {
			SetEvent(processor_context->processor_info->initialization_event); 
			HeapFree(default_heap, 0x8, processor_context);
			SetLastError(ERROR_INVALID_PARAMETER);
			return EXIT_FAILURE;
		}

		// initialize the processor ready queue.
		processor_context->processor_info->ready_queue = new QueueEx<LPEVM_THREAD>(); // the ready queue

		// initialize the processor sleep queue.
		processor_context->processor_info->sleep_queue = new QueueEx<LPEVM_THREAD>(); // the sleep queue.
		
		// add the processor to the list of available processors.
		processor_context->vm->processors.push_back(processor_context->processor_info);
		processor_context->processor_info->bInitialized = TRUE; // indicate that the processor is initialized and ready to execute threads.
		processor_context->processor_info->bIdle = TRUE;
		
		SetEvent(processor_context->processor_info->initialization_event);

		LPEVM_EXECUTION_CONTEXT execution_context = (LPEVM_EXECUTION_CONTEXT)HeapAlloc(default_heap, 0x8,
			sizeof _EVM_EXECUTION_CONTEXT);
		TlsSetValue(execution_context_tls_indx, execution_context);

		// execute queued threads.
		LPEVM_PROCESSOR processor_info = processor_context->processor_info;
		EsetVM2* VM = processor_context->vm;

		HeapFree(default_heap, 0x8, processor_context); // the processor context is no longer needed.

		DWORD64 initial_tick_count = GetTickCount64();

		while (0x1) {
			while (!processor_info->sleep_queue->empty()) {
				LPEVM_THREAD thread_info = processor_info->sleep_queue->pop();
				if (!IsBadBytePointer((LPBYTE)thread_info) && SafeMemCompare((LPBYTE)thread_info->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8) &&
					thread_info->state == EVM_THREAD_WAITING) {
					if (thread_info->wait_timeout <= 0x0) {
						InterlockedExchange((LONG*)&thread_info->state, EVM_THREAD_READY);
						VM->QueueThreadForExecution(thread_info);
					}
					else {
						thread_info->wait_timeout -= ((INT64)GetTickCount64() - (INT64)initial_tick_count);
						VM->processors[processor_info->processor_id]->sleep_queue->push(thread_info);
					}
				}
			}
			processor_info->bIdle = FALSE; // mark the processor as busy since it has a thread to execute.
			while (!processor_info->ready_queue->empty()) {
				LPEVM_THREAD thread_info = processor_info->ready_queue->pop(); // get the thread info from the front node of the ready queue.
				if (!IsBadBytePointer((LPBYTE)thread_info) && SafeMemCompare((LPBYTE)thread_info->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8)) {
					processor_info->threads_count--; // decrement the number of threads queued to the processor

					if (thread_info->state == EVM_THREAD_READY) {
						thread_info->state = EVM_THREAD_RUNNING; // update the thread state to running before executing it.

						// copy the current thread's context to the current processor's one.
						SafeMemCopy((LPBYTE)&processor_info->registers, (LPBYTE)&thread_info->context, sizeof EVM_CONTEXT);

						LPEVM_PROCESS process_info = (LPEVM_PROCESS)thread_info->lpCreatorProcess;
						if (!IsBadRange((LPBYTE)process_info, sizeof EVM_PROCESS) && process_info->loaded_module.code_rva !=
							EVM_INVALID_RVA && process_info->loaded_module.code_size &&
							!IsBadRange((LPBYTE)process_info->loaded_module.evm_module_base, process_info->loaded_module.image_size)) {

							// setup the execution context.
							execution_context->current_thread = thread_info;
							execution_context->registers = &processor_info->registers;
							execution_context->vm = VM;
							execution_context->current_processor = processor_info->processor_id;

							// execute instructions one by one, if there invalid instructions the execution stops there throughing an exception in the current processor.
							processor_info->lpExecutionUnit->Execute(process_info->loaded_module.evm_module_base +
								process_info->loaded_module.code_rva);

							ZeroMemory(execution_context, sizeof EVM_EXECUTION_CONTEXT);
						}
					}
				}
			}
			processor_info->bIdle = TRUE; // mark the processor as idle if there are no threads in its ready queue.
		}

		return EXIT_SUCCESS;
	}
	DWORD __stdcall AddEvmProcessor() {
		LPEVM_PROCESSOR_CONTEXT processor_context = (LPEVM_PROCESSOR_CONTEXT)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, sizeof EVM_PROCESSOR_CONTEXT);
		if (IsBadBytePointer((LPBYTE)processor_context)) return EVM_INVALID_PROCESSOR_ID;
		
		LPEVM_PROCESSOR processor_info = (LPEVM_PROCESSOR)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, sizeof EVM_PROCESSOR);
		if (IsBadBytePointer((LPBYTE)processor_info)) {
			HeapFree(default_heap, 0x8, processor_context);
			return EVM_INVALID_PROCESSOR_ID;
		}

		processor_info->lpExecutionUnit = new EsetVM2ExecutionUnit();
		if(IsBadRange((LPBYTE)processor_info->lpExecutionUnit, sizeof EsetVM2ExecutionUnit)) {
			HeapFree(default_heap, 0x8, processor_context);
			HeapFree(default_heap, 0x8, processor_info);
			return EVM_INVALID_PROCESSOR_ID;
		}

		processor_context->vm = this;
		processor_context->processor_info = processor_info;

		processor_info->initialization_event = CreateEventW(NULL, TRUE, FALSE, NULL);
		if(!processor_info->initialization_event) {
			HeapFree(default_heap, 0x8, processor_info);
			HeapFree(default_heap, 0x8, processor_context);
			return EVM_INVALID_PROCESSOR_ID;
		}

		HANDLE thread_handle = CreateThread(NULL, 0x0, (LPTHREAD_START_ROUTINE)EsetVM2ProcessorProc, 
			processor_context, CREATE_SUSPENDED, &processor_info->thread_id);
		if(!thread_handle ) {
			HeapFree(default_heap, 0x8, processor_info);
			HeapFree(default_heap, 0x8, processor_context);
			CloseHandle(processor_info->initialization_event);
			return EVM_INVALID_PROCESSOR_ID;
		}

		processor_info->bIdle = TRUE;
		SafeMemCopy((LPBYTE)processor_info->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8);

		DWORD processor_id = 0x0;
		INT buffer = dwProcessorMask;
		while (buffer) {
			buffer >>= 0x1;
			processor_id++;
		}
		processor_info->processor_id = processor_id;

		ResumeThread(thread_handle);
		CloseHandle(thread_handle);

		WaitForSingleObject(processor_info->initialization_event, INFINITE); // wait for the processor to start.
		CloseHandle(processor_info->initialization_event);

		if (!processor_info->bInitialized) {
			HeapFree(default_heap, 0x8, processor_info);
			return EVM_INVALID_PROCESSOR_ID;
		}
		

		dwProcessorMask |= (1 << processor_id); // enable the processor in the processor mask.

		return processor_id;
	}
	DWORD __stdcall GetIdleEvmProcessorForThread(LPEVM_THREAD thread_info) {
		for (LPEVM_PROCESSOR processor_info : processors) {
			if (processor_info->bIdle) {
				if(!thread_info || IsBadBytePointer((LPBYTE)thread_info) || 
					thread_info->dwAffinityMask & (1 << processor_info->processor_id)) return processor_info->processor_id;
			}
		}
		return EVM_INVALID_PROCESSOR_ID;
	}
	BOOLEAN __stdcall CreateEvmProcess() {
		if (IsBadBytePointer((LPBYTE)evm_file_path) || !lstrlenA(evm_file_path)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}

		LPEVM_PROCESS process_info = (LPEVM_PROCESS)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, sizeof EVM_PROCESS);
		if (IsBadBytePointer((LPBYTE)process_info)) return FALSE;

		process_info->threads = new unordered_map<DWORD32, LPEVM_THREAD>();
		if(IsBadRange((LPBYTE)process_info->threads, sizeof unordered_map<DWORD32, LPEVM_THREAD>)) {
			HeapFree(default_heap, 0x8, process_info);
			return FALSE;
		}

		// load the .evm file code and data into memory (memory access is faster than disk IO).
		
		if(!LoadEvmFile(&process_info->loaded_module)) {
			delete process_info->threads;
			HeapFree(default_heap, 0x8, process_info);
			return FALSE;
		}

		// Create the main thread.
		LPEVM_THREAD main_thread = CreateEvmThread(process_info, 0x0, 0x0, 0x1);
		if(IsBadBytePointer((LPBYTE)main_thread)) {
			delete process_info->threads;
			HeapFree(default_heap, 0x8, process_info);
			return FALSE;
		}

		processes->InsertTail(&process_info->ProcessEntry);

		return TRUE;
	}
	LPEVM_THREAD __stdcall CreateEvmThread(LPEVM_PROCESS lpCreateProcess, LPEVM_CONTEXT lpCreatorContext, ULONG start_address, BOOLEAN bMain) {
		//lpCreatorContext: register values of the thread that is creating the new thread.

		if(IsBadRange((LPBYTE)lpCreateProcess, sizeof EVM_PROCESS)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return NULL;
		}

		LPEVM_THREAD thread_info = (LPEVM_THREAD)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, sizeof EVM_THREAD);
		if (IsBadBytePointer((LPBYTE)thread_info)) return NULL;

		thread_info->WaiterThreads = new QueueEx<LPEVM_THREAD>();
		if (IsBadRange((LPBYTE)thread_info->WaiterThreads, sizeof QueueEx<LPEVM_THREAD>)) {
			HeapFree(default_heap, 0x8, thread_info);
			return NULL;
		}

		SafeMemCopy((LPBYTE)thread_info->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8);

		thread_info->dwAffinityMask = this->dwProcessorMask; // allow the thread to run on any processor

		// initialize the thread context with the creator thread context ( if provided ) or with zeroes.
		if (lpCreatorContext && !IsBadRange((LPBYTE)lpCreatorContext, sizeof EVM_CONTEXT)) 
			SafeMemCopy((LPBYTE)&thread_info->context, (LPBYTE)lpCreatorContext, sizeof EVM_CONTEXT);

		// set the thread instruction pointer to the start address provided by the caller.
		thread_info->ip = start_address;

		thread_info->dwThreadId = dwThreadId;
		thread_info->state = EVM_THREAD_READY; // the initial state of the thread is ready since it is queued to a processor for execution.
		thread_info->lpCreatorProcess = lpCreateProcess;
		thread_info->quantum = EVM_DEFAULT_THREAD_QUANTUM;

		thread_info->stack = new StackEx<DWORD32>();
		if (IsBadRange((LPBYTE)thread_info->stack, sizeof StackEx<DWORD32>)) {
			delete thread_info->WaiterThreads;
			HeapFree(default_heap, 0x8, thread_info);
			return NULL;
		}

		lpCreateProcess->threads->insert(make_pair(thread_info->dwThreadId, thread_info));
		
		InterlockedIncrement(&dwThreadId);

		thread_info->bIsMainThread = bMain;

		if (!QueueThreadForExecution(thread_info)) {
			printf_s("UNEXPECTED ERROR !! the VM is exhausted\n");
			InterlockedDecrement(&dwThreadId);
			lpCreateProcess->threads->erase(thread_info->dwThreadId);
			delete thread_info->WaiterThreads;
			HeapFree(default_heap, 0x8, thread_info);
			return NULL;
		}

		return thread_info;
	}
	BOOLEAN __stdcall QueueThreadForExecution(LPEVM_THREAD thread) {
		if (IsBadRange((LPBYTE)thread, sizeof EVM_THREAD)) {
			SetLastError(ERROR_INVALID_PARAMETER);
			return FALSE;
		}

		DWORD ideal_processor = GetIdleEvmProcessorForThread(thread);// the ideal processor is the one that is currently idle.
		if (ideal_processor != EVM_INVALID_PROCESSOR_ID) {
			// Queue the thread to the ideal processor.
			InterlockedIncrement(&processors[ideal_processor]->threads_count); // increment the number of threads queued to the processor.
			processors[ideal_processor]->ready_queue->push(thread);
		}
		else {
			// Queue the the processor that has the minimum number of threads in its ready queue.
			DWORD processor_id = EVM_INVALID_PROCESSOR_ID, min_threads_count = MAXDWORD;
			for (LPEVM_PROCESSOR processor_info : processors) {
				if (processor_info->threads_count < min_threads_count) {
					processor_id = processor_info->processor_id;
					min_threads_count = processor_info->threads_count;
				}
			}

			if (processor_id != EVM_INVALID_PROCESSOR_ID) {
				InterlockedIncrement(&processors[processor_id]->threads_count); // increment the number of threads queued to the processor.
				processors[processor_id]->ready_queue->push(thread);
			}
			else return FALSE;
		}
		return TRUE;
	}
	BOOLEAN __stdcall LoadEvmFile(LPEVM_LOADED_MODULE evm_module) {
		HANDLE file_handle = CreateFileA(evm_file_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if (file_handle == INVALID_HANDLE_VALUE) return FALSE;

		evm_module->evm_module_base = (LPBYTE)VirtualAlloc(0x0, (evm_hdr.dwCodeSize + evm_hdr.dwDataSize),
			MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); // maps the loaded .evm module to memory for fast access;
		if(IsBadBytePointer(evm_module->evm_module_base)) {
			evm_module->evm_module_base = 0x0;
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return FALSE;
		}

		evm_module->code_rva = evm_module->data_rva = EVM_INVALID_RVA;

		if (evm_hdr.dwCodeSize) {
			evm_module->code_rva = 0x0;
		}
		if (evm_hdr.dwDataSize) {
			if(evm_module->code_rva) evm_module->data_rva = evm_hdr.dwCodeSize; // the data section is located right after the code section in the memory.
			else evm_module->data_rva = 0x0; // if there is no code section, load the data section at the base of the allocated memory.
		}

		SetFilePointer(file_handle, sizeof _EVM_FILE_HEADER, 0x0, FILE_BEGIN);
		if(!ReadFile(file_handle, evm_module->evm_module_base, evm_hdr.dwCodeSize + evm_hdr.dwDataSize, NULL, NULL)) {
			CloseHandle(file_handle);
			VirtualFree(evm_module->evm_module_base, 0x0, MEM_RELEASE);
			evm_module->evm_module_base = 0x0;
			evm_module->code_rva = evm_module->data_rva = EVM_INVALID_RVA;
			return FALSE;
		}

		CloseHandle(file_handle);

		DWORD old_protection = 0x0;
		VirtualProtect(evm_module->evm_module_base, evm_hdr.dwCodeSize + evm_hdr.dwDataSize, PAGE_READONLY, &old_protection); // change the protection to read only to prevent memory changes in the module region.

		evm_module->image_size = (evm_hdr.dwCodeSize + evm_hdr.dwDataSize);
		evm_module->code_size = evm_hdr.dwCodeSize;
		evm_module->module_path = evm_file_path;

		return TRUE;
	}

	// =================================================

	ULONG dwProcessorMask, memory_capacity, dwThreadId;
	vector<LPEVM_PROCESSOR> processors;
	LPSTR evm_file_path;
	EVM_FILE_HEADER evm_hdr;
	DoublyLinkedList* processes;
	LPBYTE lpVmMemoryBase;
	INT argc;
	LPSTR* argv;
	unordered_map<ULONG, LPEVM_LOCK> locks; // used to by lock and unlock;

public:
	EsetVM2(ULONG processors_count, ULONG memory_capacity, LPSTR evm_file_path, INT argc, LPSTR* argv) {
		if (!IsEvmFileValid(evm_file_path, &evm_hdr)) {
			SetLastError(ERROR_EVM_INVALID_FILE_FORAMAT);
			printf_s("ERROR !! invalid .evm file\n");
			return;
		}

		this->argc = argc;
		this->argv = argv;

		dwProcessorMask = dwThreadId = 0x0;
		this->memory_capacity = memory_capacity;

		lpVmMemoryBase = (LPBYTE)VirtualAlloc(NULL, memory_capacity, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (IsBadRange(lpVmMemoryBase, memory_capacity)) return;

		INT path_len = lstrlenA(evm_file_path);
		if(!IsBadBytePointer((LPBYTE)evm_file_path) && path_len) {
			this->evm_file_path = (LPSTR)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, path_len + 0x1);
			if(this->evm_file_path) SafeMemCopy((LPBYTE)this->evm_file_path, (LPBYTE)evm_file_path, path_len);
		}

		for (UINT i = 0x0; i < processors_count && i < EVM_MAXIMUM_PROCESSORS_COUNT; i++) AddEvmProcessor();
		
		processes = new DoublyLinkedList();

		// Create a new EVM process to execute the provided .evm file.
		CreateEvmProcess();

		// wait for all processors. (since evm processors are implemented as threads, we don't want to terminate the VM 
		// before all processors finish their work).

		for (LPEVM_PROCESSOR processor_info : processors) {
			HANDLE thread_handle = OpenThread(SYNCHRONIZE, FALSE, processor_info->thread_id);
			if (thread_handle) {
				WaitForSingleObject(thread_handle, INFINITE);
				CloseHandle(thread_handle);
			}
		}
	}
	~EsetVM2() {
		for (LPEVM_PROCESSOR processor_info : processors) {
			while (!processor_info->ready_queue->empty()) {
				LPEVM_THREAD thread = processor_info->ready_queue->pop();
				if (!IsBadRange((LPBYTE)thread, sizeof EVM_THREAD)) HeapFree(default_heap, 0x8, thread);
			}
			delete processor_info->ready_queue;
			HeapFree(default_heap, 0x0, processor_info);
		}
		if (!IsBadRange((LPBYTE)processes, sizeof DoublyLinkedList)) {
			for (LPNODE it = processes->begin(); !IsBadBytePointer((LPBYTE)it) && it != processes->end(); it = it->next) {
				LPEVM_PROCESS process = CONTAINING_RECORD(it, EVM_PROCESS, ProcessEntry);
				if (!IsBadRange((LPBYTE)process, sizeof EVM_PROCESS)) HeapFree(default_heap, 0x8, process);
			}
			delete processes;
		}
		if (!IsBadBytePointer((LPBYTE)evm_file_path)) HeapFree(default_heap, 0x8, evm_file_path);
		if (!IsBadRange(lpVmMemoryBase, memory_capacity)) VirtualFree(lpVmMemoryBase, 0x0, MEM_RELEASE);
		for (pair<ULONG, LPEVM_LOCK> item : locks) if (!IsBadRange((LPBYTE)item.second, sizeof EVM_LOCK)) HeapFree(default_heap,
			HEAP_ZERO_MEMORY, item.second);
	}
};

// =================================================

int main(INT argc, LPSTR* argv) {
	if (argc >= 0x2) {
		// allocate the TLS index.
		execution_context_tls_indx = TlsAlloc();
		if (execution_context_tls_indx == TLS_OUT_OF_INDEXES) goto EPILOGUE;

		INT evm_argc = argc - 0x2;
		LPSTR* evm_argv = 0x0;
		if (evm_argc) {
			evm_argv = (LPSTR*)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, evm_argc * 0x8);
			for (UINT i = 0x0; i < evm_argc; i++) {
				INT arg_len = lstrlenA(argv[2 + i]);
				LPSTR arg = (LPSTR)HeapAlloc(default_heap, HEAP_ZERO_MEMORY, arg_len + 0x1);
				SafeMemCopy((LPBYTE)arg, (LPBYTE)argv[2 + i], arg_len);
				evm_argv[i] = arg;
			}
		}

		// create am EsetVM2 Vm with 1 processor, 10 pages of memory and use it to execute the .evm file provided as a command line argument.
		EsetVM2 vm(8, 10 * PAGE_SIZE, argv[0x1], evm_argc, evm_argv);

		// cleanup
		if (evm_argv) {
			for (UINT i = 0x0; i < evm_argc; i++) HeapFree(default_heap, 0x8, evm_argv[i]);
			HeapFree(default_heap, 0x8, evm_argv);
		}
	}
	else printf_s("ERROR!! missing evm file path\n");

EPILOGUE:
	getchar();// prevents the console from closing immediately after the program finishes its work.
	return 0x0;
}

void __stdcall SafeMemCopy(LPBYTE dest, LPBYTE src, SIZE_T bytes_count) {
	if (IsBadRange(dest, bytes_count) || IsBadRange(src, bytes_count) || !bytes_count) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return;
	}

	for(UINT i = 0x0; i < bytes_count; i++) dest[i] = src[i];
}

BOOLEAN __stdcall IsBadBytePointer(LPBYTE pointer) {
	if (!pointer) return TRUE;
	__try {
		BYTE buffer = *pointer;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return TRUE;
	}
	return FALSE;
}

BOOLEAN __stdcall IsBadRange(LPBYTE range_start, SIZE_T bytes_count) {
	if (!bytes_count) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	for (UINT i = 0x0; i < bytes_count; i++) if (IsBadBytePointer(&range_start[i])) return TRUE;
	return FALSE;
}

BOOLEAN __stdcall IsEvmFileValid(LPSTR file_path, LPEVM_FILE_HEADER evm_hdr) {
	if (IsBadBytePointer((LPBYTE)file_path) || !lstrlenA(file_path) || IsBadBytePointer((LPBYTE)evm_hdr)) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	HANDLE file_handle = CreateFileA(file_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, NULL);
	if (file_handle == INVALID_HANDLE_VALUE) return FALSE;

	BOOLEAN bIsValid = FALSE;

	DWORD dwBytesRead = 0x0;

	if (!ReadFile(file_handle, evm_hdr, sizeof EVM_FILE_HEADER, &dwBytesRead, NULL) ||
		dwBytesRead != sizeof EVM_FILE_HEADER) goto EPILOGUE;
	else {
		if (SafeMemCompare((LPBYTE)evm_hdr->signature, (LPBYTE)ESETVM2_SIGNATURE, 0x8) && evm_hdr->dwDataSize >=
			evm_hdr->dwInitialDataSize) {
			LARGE_INTEGER file_size = { 0x0 };
			if(GetFileSizeEx(file_handle, &file_size) && 
				file_size.QuadPart == sizeof EVM_FILE_HEADER + evm_hdr->dwCodeSize + evm_hdr->dwInitialDataSize) bIsValid = TRUE;
		}
	}


EPILOGUE:
	CloseHandle(file_handle);
	return bIsValid;
}

BOOLEAN __stdcall SafeMemCompare(LPBYTE comparand_0, LPBYTE comparand_1, SIZE_T bytes_count) {
	if(IsBadRange(comparand_0, bytes_count) || IsBadRange(comparand_1, bytes_count) || !bytes_count) {
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	for (UINT i = 0x0; i < bytes_count; i++) if (comparand_0[i] != comparand_1[i]) return FALSE;
	return TRUE;
}