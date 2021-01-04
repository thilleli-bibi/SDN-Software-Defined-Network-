
from mininet.net import Mininet
from mininet.node import Controller, OVSSwitch,RemoteController
from mininet.cli import CLI
from mininet.log import setLogLevel, info

def multiControllerNet() :
    "Create a network from semi-scratch with multiple controllers."

    net = Mininet( controller=Controller, switch=OVSSwitch )

    info( "*** Creating (reference) controllers\n" )
    c1 = net.addController( 'c1',controleur = RemoteController, ip='127.0.0.1' ,port=6633 )
    c2 = net.addController( 'c2',controleur = RemoteController, ip='127.0.0.1', port=6634 )

    info( "*** Creating switches\n" )
    s1 = net.addSwitch( 's1' )
    s2 = net.addSwitch( 's2' )
    s3 = net.addSwitch( 's3' )

    info( "*** Creating hosts\n" )
    h1 = net.addHost('h1',ip='10.0.1.2/24', defaultRoute='via 10.0.1.1')
    h2 = net.addHost('h2', ip='10.0.2.2/24', defaultRoute='via 10.0.2.1')

    info( "*** Creating links\n" )
    net.addLink( s1, h1)
    net.addLink( s2, h2) 
    net.addLink( s1, s3)
    net.addLink( s3, s2)

    info( "*** Starting network\n" )
    net.build()
    
    s2.start( [ c1 ] )
    s1.start( [ c1 ] )
    s3.start( [ c2 ] )
    info( "*** Testing network\n" )
    net.pingAll()

    info( "*** Running CLI\n" )
    CLI( net )

    info( "*** Stopping network\n" )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' ) 
    multiControllerNet()
