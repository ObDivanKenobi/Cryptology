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
             r_a = p1*p2    модуль     r_b = q1*q2
       phi(r_a) = (p1-1)(p2-1)    phi(r_b) = (q1-1)(q2-1)
     
    II. 4) Выбирается
               a     открытая экспонента   b
          1 < a < phi(r_a)           1 < b < phi(r_b)
        gcd(a, phi(r_a)) = 1       gcd(b, phi(r_b)) = 1

        5) Открытый ключ
            (r_a, a)                    (r_b, b)

        6) Вычислить секретный ключ
      alpha = a^-1 mod phi(r_a)  beta = b^-1 mod phi(r_b)

    III. Шифрование:
        m - сообщение
        m1 = m^b mod r_b - шифротекст
    IV. Расшифровка:
        m2 = m1^beta mod r_b
    */
    /// <summary>
    /// Методы для работы с RSA.
    /// </summary>
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
            return Calculations.Invert(d, r); //InvertNotCoprimeIntegers(d, r);
        }

        /// <summary>
        /// Атака на алгоритм RSA методом бесключевого чтения
        /// </summary>
        /// <param name="a">часть открытого ключа (экспонента)</param>
        /// <param name="ra">часть открытого ключа (модуль)</param>
        /// <param name="c">сообщение</param>
        /// <returns></returns>
        public static int NoKeyReadingAttack(int a, int ra, int c)
        {
            int k = 1;
            int cl = Calculations.ModPow(c, a, ra);
            while(Calculations.ModPow(cl, k, ra) != c)
                ++k;

            return Calculations.ModPow(c, k, ra); //?!
        }

        /// <summary>
        /// Атака методом общего модуля (для трёх участников)
        /// </summary>
        /// <param name="a">экспонента A</param>
        /// <param name="b">экспонента B</param>
        /// <param name="ra">модуль A</param>
        /// <param name="m1">m1 = m^a mod ra</param>
        /// <param name="m2">m2 = m^b mod ra</param>
        /// <returns></returns>
        public static int SameModuleAttack(int a, int b, int ra, int m1, int m2)
        {
            Calculations.DiophantineEquation(a, b, 1, out int x0, out int y0);
            return (int)Math.Pow(m1, x0) * (int)Math.Pow(m2, y0);
        }
    }
}
