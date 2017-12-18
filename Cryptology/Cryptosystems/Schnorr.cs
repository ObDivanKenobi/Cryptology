using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;

namespace Cryptology
{
    /*
     * I. Выбор параметров:
     * 1) p, q - простые числа, (p-1) делится на q
     *    g /in Z_p: g^q = 1 mod p, g != 1
     * 2) A выбирает секретный ключ k и вычисляет y по ф-ле
     *    y = q^-k в Z_p
     * 3) А выбирает случайное число a /in {1 ... q-1} и вычисляет
     *    r = q^a mod p
     * 4) A ---(y, r)---> B
     * 
     * II. Аутентификация:
     * В проверяет А
     * 1) выбирает случайное число e и передаёт A: B ---(e)---> A
     * 2) А вычисляет s = a + ke (mod q), A ---(s)---> B
     * 3) B проверяет, что r = g^s*y^e mod p 
     */
    
    /// <summary>
    /// Протокол идентификации Шнорра.
    /// </summary>
    public class Schnorr
    {
        /// <summary>
        /// Проверить доказательство А по схеме Шнорра.
        /// </summary>
        public static bool Check(int g, int s, int y, int e, int p, int r)
        {
            BigInteger gs = BigInteger.Pow(g, s),
                       ye = BigInteger.Pow(y, e);

            BigInteger result = (gs * ye);
            return result % p == r % p;
        }

        /// <summary>
        /// Поиск секретного ключа k.
        /// </summary>
        /// <remarks>Атака производится методом перебора.</remarks>
        /// <param name="p">модуль (исходный параметр)</param>
        /// <param name="g">часть открытого ключа</param>
        /// <param name="y">часть открытого ключа</param>
        /// <returns>секретный ключ</returns>
        public static int Attack(int p, int g, int y)
        {
            int k = 1;
            BigInteger gky = g * y;
            while (gky % p != 1)
            {
                gky *= g;
                ++k;
            }

            return k;
        }

        /// <summary>
        /// Получает справку для криптосистемы без передачи ключей.
        /// </summary>
        public static string Help()
        {
            return Resources.HelpFiles.ShnorrHelp;
        }
    }
}
