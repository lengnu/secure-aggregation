import org.junit.Test;

import java.math.BigInteger;
import java.util.Random;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: PACKAGE_NAME
 * @Author: duwei
 * @Date: 2022/11/10 14:53
 * @Description: TODO
 */
public class BigInterTest {
    @Test
    public void test1(){
        //fromByte
        byte[] arr = {(byte) 0x77,0x48, (byte) 0xCB, (byte) 0xCD};
        BigInteger bigInteger = new BigInteger(-1,arr);
        BigInteger bigInteger1 = BigInteger.probablePrime(8, new Random());
        System.out.println(bigInteger1);
        System.out.println(bigInteger1.bitLength());
        System.out.println(bigInteger.bitLength());
    }

    public void test2(){

    }
}
