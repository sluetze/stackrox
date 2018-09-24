import React, { Component } from 'react';
import PropTypes from 'prop-types';
import * as Icon from 'react-feather';

class TablePagination extends Component {
    static propTypes = {
        page: PropTypes.number.isRequired,
        totalPages: PropTypes.number.isRequired,
        setPage: PropTypes.func.isRequired
    };

    onChangePage = e => {
        let { value } = e.target;
        value = Number(value) - 1;
        this.props.setPage(value);
    };

    previousPage = () => {
        this.props.setPage(this.props.page - 1);
    };

    nextPage = () => {
        this.props.setPage(this.props.page + 1);
    };

    render() {
        const page = `${this.props.page + 1}`;
        const { totalPages } = this.props;
        return (
            <div className="flex items-center justify-end text-base-500 font-500">
                <div className="flex items-center border-l-2 border-base-200 pl-2">
                    <div className="mr-4">
                        Page
                        <input
                            type="number"
                            className="text-center border-2 border-base-200 px-1 py-1 mx-2 focus:border-primary-100 outline-none"
                            value={page}
                            min={1}
                            max={totalPages}
                            onChange={this.onChangePage}
                        />
                        of {totalPages}
                    </div>
                    <button
                        className="flex items-center rounded-full text-base-600 hover:bg-base-100 mr-2"
                        onClick={this.previousPage}
                        disabled={this.props.page === 0}
                    >
                        <Icon.ChevronLeft className="h-6 w-6" />
                    </button>
                    <button
                        className="flex items-center rounded-full text-base-600 hover:bg-base-100"
                        onClick={this.nextPage}
                        disabled={this.props.page === totalPages - 1}
                    >
                        <Icon.ChevronRight className="h-6 w-6" />
                    </button>
                </div>
            </div>
        );
    }
}

export default TablePagination;
