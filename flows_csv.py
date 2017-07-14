"""
Standalone application to convert Tetration Flows to CSV
"""
import json
import argparse
import csv


def main():
    """
    Main execution routine
    """
    parser = argparse.ArgumentParser(description='Tetration Policy to CSV')
    parser.add_argument('--maxlogfiles', type=int, default=10, help='Maximum number of log files (default is 10)')
    parser.add_argument('--debug', nargs='?',
                        choices=['verbose', 'warnings', 'critical'],
                        const='critical',
                        help='Enable debug messages.')
    parser.add_argument('--flows', default=None, help='Configuration file')
    args = parser.parse_args()

    if args.flows is None:
        print '%% No flow JSON file given'
        return

    # Load in the configuration
    try:
        with open(args.flows) as flow_file:
            flows = json.load(flow_file)
    except IOError:
        print '%% Could not load flow JSON file'
        return

    columns = map( lambda x: x.keys(), flows )
    columns = reduce( lambda x,y: x+y, columns )
    columns = list( set( columns ) )

    #Process nodes and output information to CSV
    with open( 'flows.csv', 'wb' ) as out_file:
        csv_w = csv.writer( out_file )
        csv_w.writerow( columns )

        for i_r in flows:
            csv_w.writerow( map( lambda x: i_r.get( x, "" ), columns ) )


if __name__ == '__main__':
    main()
