package cryptopals;

import cryptopals.random.MT19937Rng;

import java.util.Arrays;

public class Mt199937Cloner {

    private static final int n = 624;
    private static final int u = 11;
    private static final int s = 7;
    private static final int b = 0x9d2c5680;
    private static final int t = 15;
    private static final int c = 0xefc60000;
    private static final int l = 18;


    public MT19937Rng clone(MT19937Rng rng) {
        var state = new int[n];
        Arrays.setAll(state, q -> reverseStateElem(rng.nextInt()));
        return new MT19937Rng(state, n);
    }

    private int reverseStateElem(int y) {
        y = invertRightShiftXor(y, l);
        y = invertLeftShiftAndMaskXor(y, t, c);
        y = invertLeftShiftAndMaskXor(y, s, b);
        y = invertRightShiftXor(y, u);
        return y;
    }

    //determines x from y = x ^ (x >>> s)
    private int invertRightShiftXor(int y, int s) {
        if (s >= 16) {
            return y ^ (y >>> s);
        }

        int m = 0xffffffff << (32 - s);
        int x = y & m;

        var yMask = 1 << (31 - s);
        var xMask = 0x80000000;
        for (int i = s; i < 32; ++i) {
            var yBit = y & yMask;
            var xBit = (x & xMask) >>> s;
            x = x | (xBit ^ yBit);
            xMask = xMask >>> 1;
            yMask = yMask >>> 1;
        }

        return x;
    }

    //determines x from y = x ^ ((x << s) & mask)
    private int invertLeftShiftAndMaskXor(int y, int s, int mask) {
        if (s >= 16) {
            return y ^ ((y << s) & mask);
        }

        int m = 0xffffffff >>> (32 - s);
        int x = y & m;

        var yMask = 1 << s;
        var xMask = 1;
        for (int i = 32 - s - 1; i >= 0; --i) {
            var yBit = y & yMask;
            var xBit = ((x & xMask) << s) & mask;
            x = x | (xBit ^ yBit);
            xMask = xMask << 1;
            yMask = yMask << 1;
        }

        return x;
    }
}
