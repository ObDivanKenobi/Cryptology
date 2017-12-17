using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptology
{
    /*
        1) Берутся m, q - простые числа
           q - примитивный элемент в Zm
        2) А берёт alpha и вычисляет x = q^alpha mod m
        3) B берёт beta и вычисляет y = q^beta mod m
        Открытый ключ: (m, q, x, y)
        4) A вычисляет число k1 = y^alpha mod m
           B -//- k2 = x^beta mod m
           При этом k1 = k2 = k
        k - общий секретный ключ
        
        Взлом: решить уравнение q^alpha mod m или q^beta mod m
    */

    public class DiffiHellman
    {
        public static int CalculateSecretKey(int value, int exponent, int mod)
        {
            return Calculations.ModPow(value, exponent, mod);
        }

        public static int CalculateSecretKey(int m, int q, int x, int y)
        {
            int alpha = 1,
                powQ = q;
            while (q % m != x)
            {
                ++alpha;
                powQ *= q;
            }

            return Calculations.ModPow(y, alpha, m);
        }
    }
}
