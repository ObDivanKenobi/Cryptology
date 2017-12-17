using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptology
{
    /*
                А                          B
    I. 1) Выбор простых чисел (достаточно больших)
              p1, p2                     q1, q2
       2) Вычислить
             r_a = p1*p2               r_b = q1*q2
       phi(r_a) = (p1-1)(p2-1)    phi(r_b) = (q1-1)(q2-1)
     
    II. 4) Выбирается
               a                           b 
          1 < a < phi(r_a)           1 < b < phi(r_b)
        gcd(a, phi(r_a)) = 1       gcd(b, phi(r_b)) = 1

        5) Открытый ключ
            (r_a, a)                    (r_b, b)

        6) Вычислить закрытый ключ
      alpha = a^-1 mod phi(r_a)  beta = b^-1 mod phi(r_a)

    III. Шифрование:
        m - сообщение
        m1 = m^b mod r_b - шифротекст
    IV. Расшифровка:
        m2 = m1^beta mod r_b
    */
    public class RSA
    {
        /// <summary>
        /// Шифрование сообщения.
        /// </summary>
        /// <param name="m">сообщение</param>
        /// <param name="openKey">открытый ключ принимающей стороны,
        /// r - модуль (p1*p2 или q1*q2), e - открытая экспонента,
        /// взаимно простое с phi(r) число</param>
        /// <returns>шифротекст</returns>
        public static int Encrypt(int m, (int r, int e) openKey)
        {
            return Calculations.ModPow(m, openKey.e, openKey.r);
        }

        /// <summary>
        /// Расшифровка сообщения.
        /// </summary>
        /// <param name="m1">шифротекст</param>
        /// <param name="d">закрытый ключ</param>
        /// <param name="r">модуль (p1*p2 или q1*q2)</param>
        /// <returns>расшифрованное сообщение</returns>
        public static int Decrypt(int m1, int d, int r)
        {
            return Calculations.ModPow(m1, d, r);
        }

        /// <summary>
        /// Вычислить секретный ключ по открытому
        /// </summary>
        /// <param name="d">открытая экспонента (a или b)</param>
        /// <param name="r">модуль (r_a или r_b)</param>
        public static int CalculateSecretKey(int d, int r)
        {
            return Calculations.InvertNotCoprimeIntegers(d, r);
        }
    }
}
