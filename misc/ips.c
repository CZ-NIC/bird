#include <stdio.h>
#include <math.h>
#include <unistd.h>
#include <stdlib.h>

int h[65536];

/*
 *  Probability analysis of hashing function:
 *
 *  Let n be number of items and k number of boxes. For uniform distribution
 *  we get:
 *
 *  Expected value of "item i is in given box": Xi = 1/k
 *  Expected number of items in given box: a = EX = E(sum Xi) = sum E(Xi) = n/k
 *  Expected square value: E(X^2) = E((sum Xi)^2) = E((sum_i Xi^2) + (sum_i,j i<>j XiXj)) =
 *	= sum_i E(Xi^2) + sum_i,j i<>j E(XiXj) =
 *	= sum_i E(Xi) [Xi is binary] + sum_i,j i<>j E(XiXj) [those are independent] =
 *	= n/k + n*(n-1)/k^2
 *  Variance: var X = E(X^2) - (EX)^2 = n/k + n*(n-1)/k^2 - n^2/k^2 =
 *	= n/k - n/k^2 = a * (1-1/k)
 *  Probability of fixed box being zero: Pz = ((k-1)/k)^n = (1-1/k)^n = (1-1/k)^(ak) =
 *	= ((1-1/k)^k)^a which we can approximate by e^-a.
 */

uint hf(uint n)
{
#if 0
	n = (n ^ (n >> 16)) & 0xffff;
	n = (n ^ (n << 8)) & 0xffff;
#elif 1
	n = (n >> 16) ^ n;
	n = (n ^ (n << 10)) & 0xffff;
#elif 0
	n = (n >> 16) ^ n;
	n *= 259309;
#elif 0
	n ^= (n >> 20);
	n ^= (n >> 10);
	n ^= (n >> 5);
#elif 0
	n = (n * 259309) + ((n >> 16) * 123479);
#else
	return random();
#endif
	return n;
}

int
main(int argc, char **argv)
{
	int cnt=0;
	int i;

	int bits = atol(argv[1]);
	int z = 1 << bits;
	int max = atol(argv[2]);

	while (max--)
	  {
	    uint i, e;
	    if (scanf("%x/%d", &i, &e) != 2)
	    {
	      if (feof(stdin))
		break;
	      else
		fprintf(stderr, "BUGGG\n");
	    }
//	    i >>= (32-e);
//	    i |= (i >> e);
            cnt++;
	    h[(hf(i) >> 1*(16 - bits)) & (z-1)]++;
	  }
//	printf(">>> %d addresses\n", cnt);
#if 0
	for(i=0; i<z; i++)
		printf("%d\t%d\n", i, h[i]);
#else
{
	int min=cnt, max=0, zer=0;
	double delta=0;
	double avg = (double) cnt / z;
	double exdelta = avg*(1-1/(double)z);
	double exzer = exp(-avg);
	for(i=0; i<z; i++) {
		if (h[i] < min) min=h[i];
		if (h[i] > max) max=h[i];
		delta += (h[i] - avg) * (h[i] - avg);
		if (!h[i]) zer++;
	}
	printf("size=%5d, min=%d, max=%2d, delta=%-7.6g (%-7.6g), avg=%-5.3g, zero=%g%% (%g%%)\n", z, min, max, delta/z, exdelta, avg, zer/(double)z*100, exzer*100);
}
#endif

	return 0;
}
