all:
	gcc savePacket.c -o savePacket -lpcap
	gcc hw3.c -o hw3 -lpcap
clean:
	rm hw3
	rm savePacket
run:
	sudo ./hw3
