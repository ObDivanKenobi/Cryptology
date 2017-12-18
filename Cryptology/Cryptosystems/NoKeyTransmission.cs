using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

/// <summary>
/// Пространство 
/// </summary>
namespace Cryptology.Cryptosystems
{
    /* Криптосистема без передачи ключей
     * p - простое число
     * a * alpha = 1 (mod phi(p))
     * b * beta = 1 (mod phi(p))
     * 
     * m — сообщение, отправляемое А
     * A                            B
     * m1 = m^a mod p ------------> m1
     * m2 <------------------------ m2 = m1^b mod p
     * m3 = m2^alpha mod p -------> m3
     *                              m4 = m3^beta mod p = m
     * Сообщение получено B.
     */


    /// <summary>
    /// Представляет набор методов для работы с криптосистемой
    /// без передачи ключей.
    /// </summary>
    public class NoKeyTransmission
    {
        /// <summary>
        /// Расшифровывает исходное сообщение, используя перебор.
        /// </summary>
        /// <param name="p">открытый ключ</param>
        /// <param name="m1">первое зашифрованное сообщение от A к B</param>
        /// <param name="m2">первое зашифрованное сообщение от B к A</param>
        /// <param name="m3">второе зашифрованное сообщение от A к B</param>
        /// <returns>расшифрованное сообщение</returns>
        public static int DecryptBruteforce(int p, int m1, int m2, int m3)
        {
            return Decrypt(p, m1, m2, m3, Calculations.DiscreteLogarithmBruteforce);
        }

        /// <summary>
        /// Расшифровывает исходное сообщение, используя алгоритм Шэнкса.
        /// </summary>
        /// <param name="p">открытый ключ</param>
        /// <param name="m1">первое зашифрованное сообщение от A к B</param>
        /// <param name="m2">первое зашифрованное сообщение от B к A</param>
        /// <param name="m3">второе зашифрованное сообщение от A к B</param>
        /// <returns>расшифрованное сообщение</returns>
        public static int DecryptShanks(int p, int m1, int m2, int m3)
        {
            return Decrypt(p, m1, m2, m3, Calculations.DiscreteLogarithmShanksMethod);
        }

        /// <summary>
        /// Получает справку для криптосистемы без передачи ключей.
        /// </summary>
        public static string Help()
        {
            return Resources.HelpFiles.NoKeyTransmissionHelp;
        }

        /// <summary>
        /// Расшифровывает исходное сообщение, используя заданный метод дискретного
        /// логарифмирования.
        /// </summary>
        /// <param name="p">открытый ключ</param>
        /// <param name="m1">первое зашифрованное сообщение от A к B</param>
        /// <param name="m2">первое зашифрованное сообщение от B к A</param>
        /// <param name="m3">второе зашифрованное сообщение от A к B</param>
        /// <param name="calc">метод дискретного логарифмирования</param>
        /// <returns>расшифрованное сообщение</returns>
        static int Decrypt(int p, int m1, int m2, int m3, DiscreteLogarithmCalculator calc)
        {
            //m2 = m1^b mod p
            int b = calc(m1, m2, p);
            int beta = Calculations.InvertNotCoprimeIntegers(b, Calculations.EulersTotientFunction(p));
            return Calculations.ModPow(m3, beta, p);
        }

        /// <summary>
        /// Расшифровывает исходное сообщение.
        /// </summary>
        /// <param name="p">открытый ключ</param>
        /// <param name="b">закрытый ключ B</param>
        /// <param name="m3">второе сообщение от A к B</param>
        /// <returns></returns>
        static int Decrypt(int p, int b, int m3)
        {
            int beta = Calculations.InvertNotCoprimeIntegers(b, Calculations.EulersTotientFunction(p));
            return Calculations.ModPow(m3, beta, p);
        }
    }
}
