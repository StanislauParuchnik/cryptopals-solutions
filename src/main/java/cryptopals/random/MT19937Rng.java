package cryptopals.random;

public class MT19937Rng {


    private static final int w = 32;
    private static final int n = 624;
    private static final int m = 397;
    private static final int[] a = new int[]{0, 0x9908b0df};
    private static final int u = 11;
    private static final int s = 7;
    private static final int b = 0x9d2c5680;
    private static final int t = 15;
    private static final int c = 0xefc60000;
    private static final int l = 18;
    private static final int f = 1812433253;
    private static final int lowerMask = 0x7fffffff;
    private static final int upperMask = 0x80000000;

    private final int[] state = new int[n];
    private int stateIdx;


    public MT19937Rng(int seed) {
        initState(seed);
    }

    public void setSeed(int seed) {
        initState(seed);
    }

    private void initState(int seed) {
        state[0] = seed;
        for (stateIdx = 1; stateIdx < n; stateIdx++) {
            state[stateIdx] = f * (state[stateIdx - 1] ^ (state[stateIdx - 1] >>> (w - 2))) + stateIdx;
        }
    }

    private void twist() {
        int i = 0;
        int y;
        for (; i < n - m; i++) {
            y = (state[i] & upperMask) | (state[i + 1] & lowerMask);
            state[i] = state[i + m] ^ (y >>> 1) ^ a[y & 1];
        }
        for (; i < n - 1; i++) {
            y = (state[i] & upperMask) | (state[i + 1] & lowerMask);
            state[i] = state[i + (m - n)] ^ (y >>> 1) ^ a[y & 1];
        }
        y = (state[n - 1] & upperMask) | (state[0] & lowerMask);
        state[n - 1] = state[m - 1] ^ (y >>> 1) ^ a[y & 1];

        stateIdx = 0;
    }

    public int nextInt() {
        //implementation from wikipedia
//        int j = stateIdx - (n - 1);
//        if (j < 0) {
//            j += n;
//        }
//
//        int x = (state[stateIdx] & upperMask) | (state[j] & lowerMask);
//        int xA = (x >>> 1) & a[x & 1];
//
//        j = stateIdx - (n - m);
//        if (j < 0) {
//            j += n;
//        }
//
//        x = state[j] ^ xA;
//        state[stateIdx++] = x;
//
//        if (stateIdx >= n) {
//            stateIdx = 0;
//        }

        if (stateIdx >= n) {
            twist();
        }
        int x = state[stateIdx++];


        int y = x ^ (x >>> u);
        y ^= (y << s) & b;
        y ^= (y << t) & c;
        y ^= (y >>> l);

        return y;
    }
}
