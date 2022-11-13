import org.junit.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * @BelongsProject: Secure-Aggregation
 * @BelongsPackage: PACKAGE_NAME
 * @Author: duwei
 * @Date: 2022/11/10 16:36
 * @Description: TODO
 */
public class RandomTest {

    @Test
    public void test(){
        byte[] aa = {0x21,0x31,0x24,0x56};
        Random random = new Random(324);
        random.nextBytes(aa);
        System.out.println(Arrays.toString(aa));
        random.nextBytes(aa);
        System.out.println(Arrays.toString(aa));

    }
}
