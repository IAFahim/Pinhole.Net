using System.Net;

namespace Pinhole.Sim;

internal readonly record struct Subnet(IPAddress Base, int PrefixLength)
{
    public static Subnet Parse(string cidr)
    {
        int slash = cidr.IndexOf('/');
        return new Subnet(IPAddress.Parse(cidr[..slash]), int.Parse(cidr[(slash + 1)..]));
    }

    public bool Contains(IPEndPoint endpoint)
    {
        byte[] address = Normalize(endpoint.Address);
        byte[] baseline = Normalize(Base);
        if (address.Length != baseline.Length)
        {
            return false;
        }

        int fullBytes = PrefixLength / 8;
        for (int i = 0; i < fullBytes; i++)
        {
            if (address[i] != baseline[i])
            {
                return false;
            }
        }

        int remainderBits = PrefixLength % 8;
        if (remainderBits == 0)
        {
            return true;
        }

        byte mask = (byte)(0xFF << (8 - remainderBits));
        return (address[fullBytes] & mask) == (baseline[fullBytes] & mask);
    }

    private static byte[] Normalize(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4().GetAddressBytes() : address.GetAddressBytes();
}
