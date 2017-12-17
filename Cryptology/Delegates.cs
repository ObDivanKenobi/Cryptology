namespace Cryptology
{
    /// <summary>
    /// Решение сравнения <paramref name="a"/>^x = <paramref name="b"/> (mod <paramref name="m"/>) (перебор степеней <paramref name="a"/> для нахождения x).
    /// </summary>
    public delegate int DiscreteLogarithmCalculator(int a, int b, int m);
}