using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace Cryptology
{
    public static class Calculations
    {
        /// <summary>
        /// Решение сравнения a^x = b (mod m) (перебор степеней a для нахождения x).
        /// </summary>
        public static int DiscreteLogarithmBruteforce(int a, int b, int m)
        {
            int x = 1;
            BigInteger an = a;
            while (an % m != b)
            {
                an *= a;
                ++x;
            }

            return x;
        }

        /// <summary>
        /// Решение сравнения a^x = b (mod m) (Алгоритм Шенкса).
        /// </summary>
        public static int DiscreteLogarithmShanksMethod(int a, int b, int m)
        {
            int n = (int)Math.Sqrt(m) + 1;
            BigInteger an = 1;
            for (int i = 0; i < n; ++i)
                an = (an * a) % m;

            var values = new Hashtable();
            BigInteger current = an;
            for (int i = 1; i <= n; ++i)
            {
                if (!values.ContainsKey(current))
                    values[current] = i;

                current = (current * an) % m;
            }

            current = b;
            for (int i = 0; i <= n; ++i)
            {
                if (values.ContainsKey(current))
                {
                    BigInteger answer = (int)values[current] * n - i;
                    if (answer < m)
                        return (int)answer;
                }

                current = (current * a) % m;
            }
            return -1;
        }

        /// <summary>
        /// Решение сравнения x^<paramref name="a"/> = <paramref name="b"/> (mod <paramref name="m"/>) (перебор значений x^<paramref name="a"/>).
        /// </summary>
        public static int PowerComparisonBruteforce(int a, int b, int m)
        {
            if (b == 0)
                return m;
            
            int x = 1;
            BigInteger xa = BigInteger.Pow(x, a);

            while ( xa % m != b)
            {
                ++x;
                xa = BigInteger.Pow(x, a);
            }

            return x;
        }

        /// <summary>
        /// Проверка числа на простоту.
        /// </summary>
        public static bool IsPrime(int n)
        {
            if (n < 0)
                throw new ArgumentException("Только натуральное число можно проверить на простоту");
            if (n == 1)
                return false;

            int numberSqrt = (int)Math.Round(Math.Sqrt(n));
            for (int i = 2; i <= numberSqrt; ++i)
                if (n % i == 0)
                    return false;

            return true;
        }

        /// <summary>
        /// Разложение числа на простые множители.
        /// </summary>
        public static Dictionary<int, int> Factorize(int n)
        {
            if (IsPrime(n))
                return new Dictionary<int, int> { [n] = 1 };

            var factors = new Dictionary<int, int>();
            int numberSqrt = (int)Math.Round(Math.Sqrt(n));

            for(int i = 2; i < numberSqrt; ++i)
                while(n % i == 0)
                {
                    if (factors.ContainsKey(i))
                        factors[i]++;
                    else
                        factors[i] = 1;

                    n /= i;
                }

            if (n != 1)
                factors[n] = 1;

            return factors;
        }

        /// <summary>
        /// Вычисление функции Эйлера.
        /// </summary>
        public static int EulersTotientFunction(int n)
        {
            var factors = Factorize(n);
            int result = 1;

            foreach (var p in factors)
                result *= (int)Math.Pow(p.Key, p.Value - 1) * (p.Key - 1);

            return result;
        }

        /// <summary>
        /// Подсчёт количества примитивных элементов в поле вычетов по модулю m.
        /// </summary>
        public static int CountPrimitiveElements(int m)
        {
            return EulersTotientFunction(m - 1);
        }

        /// <summary>
        /// Является ли <paramref name="n"/> примитивным элементом в поле вычетов по модулю <paramref name="m"/>.
        /// </summary>
        public static bool IsPrimitiveElement(int number, int m)
        {
            if (!IsPrime(m))
                throw new ArgumentException("Модуль должен быть простым числом!");

            int n = m - 1;
            var factors = Factorize(n);
            
            foreach(var p in factors)
            {
                BigInteger modPow = BigInteger.ModPow(number, new BigInteger(n / p.Key), m);
                if (modPow == BigInteger.One)
                    return false;
            }

            return true;
        }

        /// <summary>
        /// Поиск всех примитивных элементов в поле вычетов по модулю <paramref name="m"/>.
        /// </summary>
        public static List<int> FindPrimitiveElements(int m)
        {
            if (!IsPrime(m))
                throw new ArgumentException("Модуль должен быть простым числом!");

            var result = new List<int>();
            int n = m - 1;
            var factors = Factorize(n);

            for (int number = 1; number <= n; ++number)
            {
                bool ok = true;
                foreach (var p in factors)
                {
                    ok &= BigInteger.ModPow(number, new BigInteger(n / p.Key), m) != BigInteger.One;
                    if (!ok)
                        break;
                }

                if (ok)
                    result.Add(number);
            }

            return result;
        }
    }
}
