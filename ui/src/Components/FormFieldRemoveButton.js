import React from 'react';
import PropTypes from 'prop-types';
import * as Icon from 'react-feather';

function FormFieldRemoveButton({ field, onClick, className }) {
    function handleClick() {
        return onClick(field);
    }
    return (
        <div className="flex">
            <button
                className={`${className} items-center px-3 text-center flex border-2 `}
                onClick={handleClick}
                type="button"
            >
                <Icon.X className="w-4 h-4" />
            </button>
        </div>
    );
}

FormFieldRemoveButton.propTypes = {
    field: PropTypes.string.isRequired,
    onClick: PropTypes.func.isRequired,
    className: PropTypes.string,
};

FormFieldRemoveButton.defaultProps = {
    className:
        'ml-2 p-1 rounded-r-sm text-base-100 uppercase text-alert-700 hover:text-alert-800 bg-alert-200 hover:bg-alert-300 border-alert-300 rounded',
};

export default FormFieldRemoveButton;
