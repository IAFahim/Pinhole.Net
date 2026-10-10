using System.Net;
using System.Net.Sockets;
using Pinhole;

// One owned process and fresh ticket per physical trial. A listening socket is
// not proof that the host firewall permits this port from the phone.
int port = 0;
bool directUdp = true;
bool portMapping = true;
bool primaryDirectOnly = false;
for (int i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--port":
            if (++i >= args.Length || !int.TryParse(args[i], out port) || port is < 1 or > 65535)
                throw new ArgumentException("--port requires a listening port from 1 through 65535");
            break;
        case "--disable-direct-udp": directUdp = false; break;
        case "--disable-port-mapping": portMapping = false; break;
        case "--primary-direct-only": primaryDirectOnly = true; break;
        default: throw new ArgumentException("Unknown echo-host argument: " + args[i]);
    }
}

PinholeNode node;
try
{
    node = await PinholeNode.BindAsync(new PinholeOptions
    {
        Bind = new IPEndPoint(IPAddress.Any, port),
        ReceiveBufferCapacity = 256,
        EnableTcpTransport = true,
        EnableDirectUdp = directUdp,
        EnablePortMapping = portMapping,
    });
}
catch (SocketException ex)
{
    Console.Error.WriteLine($"BIND_FAILED socket-error={ex.SocketErrorCode} native-error={ex.NativeErrorCode}");
    return 1;
}
await using var ownedNode = node;
if (node.TcpListeningPort != node.LocalPort)
{
    Console.Error.WriteLine("TCP_BIND_FAILED: the sidecar did not bind the advertised primary port");
    return 1;
}
Console.WriteLine($"HOST_PID={Environment.ProcessId} PORT={node.LocalPort} TCP_PORT={node.TcpListeningPort} DIRECT_UDP={directUdp} PORT_MAPPING={portMapping}");
var code = Pinhole.ConnectionString.Parse(node.ConnectionString);
if (primaryDirectOnly)
{
    var targets = code.Candidates.Where(candidate => candidate.Kind == CandidateKind.Direct
        && candidate.Address.Port == node.LocalPort
        && candidate.Address.AddressFamily == AddressFamily.InterNetwork
        && !IPAddress.IsLoopback(candidate.Address.Address)).ToArray();
    if (targets.Length == 0)
        throw new InvalidOperationException("No non-loopback primary IPv4 endpoint is available for this diagnostic");
    code = new Pinhole.ConnectionString(code.PeerId, targets, code.NatHint, code.StaticKey, code.EndpointKey);
}
Console.WriteLine("TICKET_PROFILE=" + (primaryDirectOnly ? "primary-ipv4-direct" : "full"));
Console.WriteLine("TICKET " + code);
await using var peer = await node.AcceptAsync();
Console.WriteLine($"PEER encrypted={peer.IsEncrypted} kind={peer.Path.Kind} transport={peer.Path.Transport} remote={peer.Path.Remote}");
long echoes = 0;
while (await peer.ReceiveAsync() is { } payload)
{
    var before = peer.Path;
    peer.Send(payload.Span);
    if (++echoes <= 5 || echoes == 48 || echoes % 50 == 0)
        Console.WriteLine($"echo {echoes} rxpath={before.Kind} rxtransport={before.Transport} txpath={peer.Path.Kind} txtransport={peer.Path.Transport}");
}
Console.WriteLine($"CLOSED echoes={echoes}");
return 0;
