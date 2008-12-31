unsigned short checksum(const void *_buf, int len)
{
	const unsigned short *buf = _buf;
	unsigned sum = 0;

	while (len >= 2) {
		sum += *buf ++;

		if (sum & 0x80000000) {
			sum = (sum & 0xffff) + (sum >> 16);
		}

		len -= 2;
	}

	if (len) {
		unsigned char temp[2];

		temp[0] = *(unsigned char *) buf;
		temp[1] = 0;

		sum += *(unsigned short *) temp;
	}

	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	return ~sum;
}
